import { connect, checkServerIdentity } from 'node:tls';
import { Agent, request } from 'node:https';
import { isIP } from 'node:net';
import type { Profile } from './profiles.js';
import { ToolError } from './security.js';
import { setTimeout as delay } from 'node:timers/promises';

export interface ReadBudget { deadline: number; bytes: number }
export interface PeerIdentity { leaf: string; address: string }
interface Mutation {
  method: string;
  body: string | undefined;
  status: number;
  peer: PeerIdentity;
  beforeSend: () => Promise<void>;
}
export function readBudget(): ReadBudget { return { deadline: Date.now() + 30_000, bytes: 8 * 1024 * 1024 }; }

let active = 0;
const waiting: (() => void)[] = [];

class Retryable extends ToolError {
  constructor(readonly wait: number) { super('UPSTREAM_ERROR', 'API temporarily unavailable.'); }
}

export async function readJson(profile: Profile, apiKey: string, path: string, budget = readBudget(), peer?: PeerIdentity): Promise<unknown> {
  const deadline = Math.min(budget.deadline, Date.now() + 10_000);
  const timeout = () => new ToolError('TIMEOUT', 'API request exceeded its deadline.');
  if (active >= 2) {
    await new Promise<void>((resolve, reject) => {
      const resume = () => { clearTimeout(timer); resolve(); };
      const timer = setTimeout(() => {
        waiting.splice(waiting.indexOf(resume), 1);
        reject(timeout());
      }, Math.max(0, deadline - Date.now()));
      waiting.push(resume);
    });
  } else active++;
  try {
    for (let attempt = 0; ; attempt++) {
      if (Date.now() >= deadline) throw timeout();
      try { return await requestJson(profile, apiKey, path, deadline, budget, attempt < 2, peer); }
      catch (error) {
        if (!(error instanceof Retryable) || attempt >= 2) throw error;
        if (Date.now() + error.wait >= deadline) throw timeout();
        await delay(error.wait);
      }
    }
  } finally {
    const resume = waiting.shift();
    if (resume) resume();
    else active--;
  }
}

// Mutations deliberately bypass the read retry loop.
export async function sendMutation(profile: Profile, apiKey: string, path: string, mutation: Mutation): Promise<unknown> {
  return requestJson(profile, apiKey, path, Date.now() + 10_000, readBudget(), false, undefined, mutation);
}

async function requestJson(profile: Profile, apiKey: string, path: string, expires: number, budget: ReadBudget, retry: boolean,
  identity?: PeerIdentity, mutation?: Mutation): Promise<unknown> {
  const origin = new URL(profile.origin);
  const hostname = origin.hostname.replace(/^\[|\]$/g, '');
  // No HTTP bytes or credentials are written until chain, name, validity and pin pass.
  const socket = connect({ host: profile.tls?.connectAddress ?? hostname, port: Number(origin.port || 443),
    ...(isIP(hostname) ? {} : { servername: hostname }), rejectUnauthorized: true,
    ...(profile.tls ? { ca: profile.tls.trustedCertificatePem } : {}),
  });
  const deadline = setTimeout(() => socket.destroy(new ToolError('TIMEOUT', 'API request exceeded its deadline.')), Math.max(0, expires - Date.now()));
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once('error', reject);
      socket.once('secureConnect', () => {
        const peer = socket.getPeerCertificate();
        const nameError = checkServerIdentity(hostname, peer);
        if (!socket.authorized || nameError || (profile.tls && peer.fingerprint256?.replaceAll(':', '').toLowerCase() !== profile.tls.peerFingerprintSha256.toLowerCase())) {
          reject(new Error('TLS identity rejected'));
        } else {
          const observed = { leaf: peer.fingerprint256.replaceAll(':', '').toLowerCase(), address: socket.remoteAddress! };
          const expected = mutation?.peer ?? identity;
          if (expected && (mutation || expected.leaf) && (observed.leaf !== expected.leaf || observed.address !== expected.address)) {
            reject(new ToolError('WRITE_DRIFT', 'TLS identity or route changed since preview.'));
          } else {
            if (identity && !identity.leaf) Object.assign(identity, observed);
            resolve();
          }
        }
      });
    });
  } catch (error) {
    clearTimeout(deadline);
    socket.destroy();
    if (error instanceof ToolError) throw error;
    if (error instanceof Error && (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE'].includes((error as NodeJS.ErrnoException).code ?? '') || error.message === 'socket hang up')) {
      if (retry) throw new Retryable(100);
      throw new ToolError('TRANSPORT_FAILED', 'API request failed.');
    }
    throw new ToolError('TLS_REJECTED', 'TLS chain, validity, hostname or peer fingerprint verification failed.');
  }
  const agent = new Agent({ maxSockets: 1 });
  agent.createConnection = () => socket;
  try {
    if (mutation) await mutation.beforeSend();
    return await new Promise<unknown>((resolve, reject) => {
      const call = request(new URL(`/proxy/network/integration${path}`, origin), {
        method: mutation?.method ?? 'GET', agent,
        headers: { 'X-API-KEY': apiKey, Accept: 'application/json',
          ...(mutation?.body !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(mutation.body) } : {}) },
      }, response => {
        const status = response.statusCode ?? 0;
        if (status !== (mutation?.status ?? 200)) {
          const after = response.headers['retry-after'];
          // Retry only bounded delta-seconds. Never follow redirects with credentials.
          const safeDelay = typeof after === 'string' && /^(0|1|2)$/.test(after) ? Number(after) * 1000 : undefined;
          response.destroy();
          if (retry && ((status === 429 && safeDelay !== undefined) || [502, 503, 504].includes(status))) {
            reject(new Retryable(status === 429 ? safeDelay! : 100));
          } else reject(new ToolError('UPSTREAM_ERROR', `API request failed (HTTP ${status}).`));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          budget.bytes -= chunk.length;
          if (size > 1024 * 1024 || budget.bytes < 0) { response.destroy(); reject(new ToolError('READ_INCOMPLETE', 'API response exceeded its byte budget. Narrow the filter.')); }
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          if (mutation && mutation.body === undefined && size === 0) { resolve(null); return; }
          try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new ToolError('RESPONSE_INVALID', 'API response is not JSON.')); }
        });
      });
      call.once('error', reject);
      call.end(mutation?.body);
    });
  } catch (error) {
    if (error instanceof ToolError) throw error;
    if (retry) throw new Retryable(100);
    throw new ToolError('TRANSPORT_FAILED', 'API request failed.');
  } finally { clearTimeout(deadline); agent.destroy(); socket.destroy(); }
}
