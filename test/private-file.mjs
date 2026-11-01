import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateFiles } from '../dist/private-file.js';
import { Profiles, validateProfile } from '../dist/profiles.js';
import { Redactor } from '../dist/security.js';

for (const { name, relative, exclusive, flushed } of [
  { name: 'new directory chain', relative: ['new', 'leaf'], exclusive: false,
    flushed: [['new', 'leaf'], ['new'], []] },
  { name: 'existing directory', relative: [], exclusive: false, flushed: [[]] },
  { name: 'exclusive claim', relative: ['leaf'], exclusive: true,
    flushed: [['leaf'], []] },
]) {
  test(`Private directory sync covers ${name} without flushing unrelated ancestors`, { skip: process.platform === 'win32' }, async () => {
    const root = await mkdtemp(join(tmpdir(), 'unifi-directory-sync-'));
    const synced = [];
    class ObservedFiles extends PrivateFiles {
      async syncDirectory(path) {
        synced.push(path);
        await super.syncDirectory(path);
      }
    }
    try {
      const files = new ObservedFiles();
      await files.directory(root);
      assert.equal(synced.at(-1), '/', 'Initial directory setup persists ancestors through the filesystem root');
      synced.length = 0;
      await files.directory(join(root, ...relative), exclusive);
      assert.deepEqual(synced, flushed.map(parts => join(root, ...parts)));
    } finally { await rm(root, { recursive: true, force: true }); }
  });
}

test('Failed directory sync leaves ancestor durability unconfirmed', { skip: process.platform === 'win32' }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'unifi-directory-sync-'));
  const synced = [];
  let fail = true;
  class ObservedFiles extends PrivateFiles {
    async syncDirectory(path) {
      synced.push(path);
      if (path === root && fail) throw new Error('synthetic ancestor sync failure');
      await super.syncDirectory(path);
    }
  }
  try {
    const files = new ObservedFiles();
    const path = join(root, 'leaf');
    await assert.rejects(files.directory(path), { message: 'synthetic ancestor sync failure' });
    fail = false;
    synced.length = 0;
    await files.directory(path);
    assert.equal(synced[0], path);
    assert.equal(synced.at(-1), '/', 'A failed flush cannot justify skipping ancestors on retry');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Windows private-file branch protects directories and temporary files before publishing', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'unifi-windows-branch-'));
  const path = join(directory, 'config.json');
  const acl = [];
  const files = new PrivateFiles('win32', (path, action, directory) => { acl.push({ path, action, directory }); });
  try {
    await files.write(path, 'new config');
    assert.equal(await readFile(path, 'utf8'), 'new config');
    assert.equal(acl[0].path, directory);
    assert.equal(acl[0].action, 'restrict');
    assert.equal(acl[0].directory, true);
    assert.equal(acl[1].action, 'restrict');
    assert.equal(acl[1].directory, false);
    assert.notEqual(acl[1].path, path, 'ACL is set on exclusive temporary file before rename');
    assert.equal(await files.read(path), 'new config');
    assert.deepEqual(acl.at(-1), { path, action: 'verify', directory: false });
    await files.read(path, true);
    assert.deepEqual(acl.at(-1), { path, action: 'verify', directory: false });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('Failed Windows ACL application preserves prior configuration and removes temporary files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'unifi-failed-write-'));
  const path = join(directory, 'config.json');
  await writeFile(path, 'prior config');
  const files = new PrivateFiles('win32', (_path, _action, directory) => {
    if (!directory) throw new Error('synthetic ACL refusal');
  });
  try {
    await assert.rejects(files.write(path, 'replacement'), { code: 'CONFIG_INSECURE' });
    assert.equal(await readFile(path, 'utf8'), 'prior config');
    assert.deepEqual(await readdir(directory), ['config.json']);
    await assert.rejects(files.read(path, true), { code: 'CONFIG_INSECURE' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const [name, refused, consume] of [
  ['default profile', 'config', profiles => profiles.select()],
  ['named profile', 'config', profiles => profiles.select('only')],
  ['profile list', 'config', profiles => profiles.list()],
  ['configure input', 'input', (profiles, paths) => profiles.configure('new', paths.input)],
  ['configure existing config', 'config', (profiles, paths) => profiles.configure('new', paths.input)],
  ['file secret', 'secret', (profiles, paths) => profiles.secret({ apiKey: { file: paths.secret } }, new Redactor())],
]) {
  test(`Windows ${name} refuses a file writable by another user`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'unifi-windows-read-'));
    const paths = { config: join(directory, 'config.json'), input: join(directory, 'profile.json'), secret: join(directory, 'key.txt') };
    const profile = { origin: 'https://localhost', apiKey: { env: 'SYNTHETIC_KEY' } };
    const config = JSON.stringify({ version: 1, profiles: { only: profile } });
    try {
      await writeFile(paths.config, config);
      await writeFile(paths.input, JSON.stringify(profile));
      await writeFile(paths.secret, 'synthetic-key');
      const files = new PrivateFiles('win32', (path, action) => {
        if (path === paths[refused] && action === 'verify') throw new Error('synthetic grant to another user');
      });
      const profiles = new Profiles(paths.config, files, {});
      await assert.rejects(consume(profiles, paths), { code: 'CONFIG_INSECURE' });
      assert.equal(await readFile(paths.config, 'utf8'), config);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

for (const path of ['\\\\server\\share\\key.txt', '\\\\?\\C:\\Secrets\\key.txt', '\\\\.\\C:\\Secrets\\key.txt', 'C:key.txt', '/key.txt']) {
  test(`Windows reference boundary refuses non-local-drive path ${path}`, () => {
    assert.throws(() => validateProfile({ origin: 'https://localhost', apiKey: { file: path } }, 'win32'), { code: 'CONFIG_INVALID' });
  });
}
test('Windows reference boundary accepts an absolute local drive reference', () => {
  assert.deepEqual(validateProfile({ origin: 'https://localhost', apiKey: { file: 'C:\\Secrets\\key.txt' } }, 'win32').apiKey,
    { file: 'C:\\Secrets\\key.txt' });
});
