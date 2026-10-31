import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PrivateFiles } from '../dist/private-file.js';
import { validateProfile } from '../dist/profiles.js';

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
    assert.equal(await files.read(path, false, true), 'new config');
    assert.deepEqual(acl.at(-1), { path, action: 'verify', directory: false });
    await files.read(path);
    assert.deepEqual(acl.at(-1), { path, action: 'inspect', directory: false });
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
    await assert.rejects(files.read(path, true, true), { code: 'CONFIG_INSECURE' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const path of ['\\\\server\\share\\key.txt', '\\\\?\\C:\\Secrets\\key.txt', '\\\\.\\C:\\Secrets\\key.txt', 'C:key.txt', '/key.txt']) {
  test(`Windows reference boundary refuses non-local-drive path ${path}`, () => {
    assert.throws(() => validateProfile({ origin: 'https://localhost', apiKey: { file: path } }, 'win32'), { code: 'CONFIG_INVALID' });
  });
}
test('Windows reference boundary accepts an absolute local drive reference', () => {
  assert.deepEqual(validateProfile({ origin: 'https://localhost', apiKey: { file: 'C:\\Secrets\\key.txt' } }, 'win32').apiKey,
    { file: 'C:\\Secrets\\key.txt' });
});
