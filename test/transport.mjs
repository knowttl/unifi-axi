import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { readJson } from '../dist/transport.js';

let temporary, key, cert, fingerprint;
before(() => {
  temporary = mkdtempSync(join(process.cwd(), '.transport-test-'));
  const result = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', 'server.key', '-out', 'server.crt', '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost'], { cwd: temporary, encoding: 'utf8' });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  key = readFileSync(join(temporary, 'server.key'));
  cert = readFileSync(join(temporary, 'server.crt'), 'utf8');
  fingerprint = new X509Certificate(cert).fingerprint256.replaceAll(':', '').toLowerCase();
});
after(() => { if (temporary) rmSync(temporary, { recursive: true, force: true }); });

async function service(t) {
  const requests = [];
  let connections = 0;
  const server = createServer({ key, cert }, (request, response) => {
    requests.push({ path: request.url, key: request.headers['x-api-key'] });
    response.end(JSON.stringify({ applicationVersion: '11.0.97' }));
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  server.on('connection', () => { connections++; });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const profile = { origin: `https://localhost:${server.address().port}`, tls: {
    trustedCertificatePem: cert, peerFingerprintSha256: fingerprint, connectAddress: '127.0.0.1',
  } };
  return { server, profile, requests, connections: () => connections };
}

test('retries a reset before TLS and succeeds', async t => {
  const fixture = await service(t);
  fixture.server.prependOnceListener('connection', socket => socket.resetAndDestroy());
  assert.deepEqual(await readJson(fixture.profile, 'synthetic-key', '/v1/info'), { applicationVersion: '11.0.97' });
  assert.equal(fixture.connections(), 2);
  assert.deepEqual(fixture.requests, [{ path: '/proxy/network/integration/v1/info', key: 'synthetic-key' }]);
});

test('never retries a pin mismatch or sends credentials', async t => {
  const fixture = await service(t);
  fixture.profile.tls.peerFingerprintSha256 = '0'.repeat(64);
  await assert.rejects(readJson(fixture.profile, 'synthetic-key', '/v1/info'), error => error.code === 'TLS_REJECTED');
  assert.equal(fixture.connections(), 1);
  assert.deepEqual(fixture.requests, []);
});
