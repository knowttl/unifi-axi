import { connect, checkServerIdentity } from 'node:tls';
import { Agent, request } from 'node:https';
import { isIP } from 'node:net';
import type { Profile } from './profiles.js';
import { ToolError } from './security.js';

export async function readJson(profile: Profile, apiKey: string, path: string): Promise<unknown> {
  const origin = new URL(profile.origin);
  const hostname = origin.hostname.replace(/^\[|\]$/g, '');
  // No HTTP bytes or credentials are written until chain, name, validity and pin pass.
  const socket = connect({ host: profile.tls?.connectAddress ?? hostname, port: Number(origin.port || 443),
    ...(isIP(hostname) ? {} : { servername: hostname }), rejectUnauthorized: true,
    ...(profile.tls ? { ca: profile.tls.trustedCertificatePem } : {}),
  });
  try {
    await new Promise<void>((resolve, reject) => {
      socket.setTimeout(5000, () => socket.destroy(new Error('TLS timeout')));
      socket.once('error', reject);
      socket.once('secureConnect', () => {
        const peer = socket.getPeerCertificate();
        const nameError = checkServerIdentity(hostname, peer);
        if (!socket.authorized || nameError || (profile.tls && peer.fingerprint256?.replaceAll(':', '').toLowerCase() !== profile.tls.peerFingerprintSha256.toLowerCase())) {
          reject(new Error('TLS identity rejected'));
        } else resolve();
      });
    });
  } catch {
    socket.destroy();
    throw new ToolError('TLS_REJECTED', 'TLS chain, validity, hostname or peer fingerprint verification failed.');
  }
  const agent = new Agent({ maxSockets: 1 });
  agent.createConnection = () => socket;
  try {
    return await new Promise<unknown>((resolve, reject) => {
      const call = request(new URL(`/proxy/network/integration${path}`, origin), {
        method: 'GET', agent,
        headers: { 'X-API-KEY': apiKey, Accept: 'application/json' },
      }, response => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 1024 * 1024) { response.destroy(); reject(new ToolError('RESPONSE_INVALID', 'API response exceeds limit.')); }
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          if (response.statusCode !== 200) return reject(new ToolError('UPSTREAM_ERROR', `API request failed (HTTP ${response.statusCode}).`));
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new ToolError('RESPONSE_INVALID', 'API response is not JSON.')); }
        });
      });
      call.setTimeout(5000, () => call.destroy(new Error('HTTP timeout')));
      call.once('error', reject);
      call.end();
    });
  } catch (error) {
    if (error instanceof ToolError) throw error;
    throw new ToolError('TRANSPORT_FAILED', 'API request failed.');
  } finally { agent.destroy(); socket.destroy(); }
}
