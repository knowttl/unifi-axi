import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { readJson, sendMutation } from '../dist/transport.js';
import vendorErrors from './fixtures/vendor-errors.json' with { type: 'json' };

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

async function service(t, respond = (request, response) => response.end(JSON.stringify({ applicationVersion: '11.0.97' }))) {
  const requests = [];
  let connections = 0;
  const server = createServer({ key, cert }, (request, response) => {
    requests.push({ path: request.url, key: request.headers['x-api-key'] });
    respond(request, response);
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

for (const [status, code] of [[400, 'UPSTREAM_ERROR'], [404, 'NOT_FOUND'], [500, 'UPSTREAM_ERROR']]) {
  test(`preserves bounded vendor diagnostics for HTTP ${status}`, async t => {
    const fixture = await service(t, (request, response) => {
      response.statusCode = status;
      response.end(JSON.stringify({ ...vendorErrors.wifiFastRoaming,
        message: `${vendorErrors.wifiFastRoaming.message}\nsynthetic-key`, ignored: 'not retained' }));
    });
    await assert.rejects(readJson(fixture.profile, 'synthetic-key', '/v1/info'), error => {
      assert.equal(error.code, code);
      assert.deepEqual(error.upstream, { status, ...vendorErrors.wifiFastRoaming,
        message: `${vendorErrors.wifiFastRoaming.message} [REDACTED]` });
      assert.equal(error.message.includes('synthetic-key'), false);
      return true;
    });
    assert.equal(fixture.requests.length, 1);
  });
}

test('keeps an error status when the vendor returns a non-JSON error page', async t => {
  const fixture = await service(t, (request, response) => {
    response.statusCode = 404;
    response.end('<html>private diagnostic</html>');
  });
  await assert.rejects(readJson(fixture.profile, 'synthetic-key', '/v1/info'), error =>
    error.code === 'NOT_FOUND' && error.upstream.status === 404 && !error.message.includes('private diagnostic'));
});

test('keeps a definitive refusal when its error body exceeds the byte budget', async t => {
  const fixture = await service(t, (request, response) => {
    response.statusCode = 400;
    response.end('x'.repeat(1024 * 1024 + 1));
  });
  await assert.rejects(readJson(fixture.profile, 'synthetic-key', '/v1/info'), error =>
    error.code === 'UPSTREAM_ERROR' && error.upstream.status === 400);
});

test('removes request credentials from vendor mutation diagnostics', async t => {
  const peer = { leaf: '', address: '' };
  const fixture = await service(t, (request, response) => {
    if (request.method === 'GET') { response.end('{}'); return; }
    response.statusCode = 400;
    response.end(JSON.stringify({ code: 'BAD_REQUEST', message: 'Refused synthetic-passphrase and synthetic-key' }));
  });
  await readJson(fixture.profile, 'synthetic-key', '/v1/info', undefined, peer);
  await assert.rejects(sendMutation(fixture.profile, 'synthetic-key', '/v1/example', {
    method: 'POST', body: JSON.stringify({ securityConfiguration: { passphrase: 'synthetic-passphrase' } }),
    status: 201, peer, beforeSend: async () => {},
  }), error => error.upstream.message === 'Refused [REDACTED] and [REDACTED]');
  assert.equal(fixture.requests.length, 2);
});

test('uses the certificate DNS name with a pinned IP connection destination', async t => {
  const fixture = await service(t);
  const pinnedIp = { ...fixture.profile, origin: fixture.profile.origin.replace('localhost', '127.0.0.1') };
  await assert.rejects(readJson(pinnedIp, 'synthetic-key', '/v1/info'), error => error.code === 'TLS_REJECTED');
  assert.equal(fixture.requests.length, 0);
  assert.deepEqual(await readJson(fixture.profile, 'synthetic-key', '/v1/info'), { applicationVersion: '11.0.97' });
  assert.equal(fixture.requests.length, 1);
});
