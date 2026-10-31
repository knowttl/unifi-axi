import { Socket } from 'node:net';
import dgram from 'node:dgram';
import fs from 'node:fs/promises';
import { constants, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import https from 'node:https';
import tls from 'node:tls';

const connect = Socket.prototype.connect;
Socket.prototype.connect = function (this: Socket, ...args: unknown[]) {
  const first = (Array.isArray(args[0]) ? args[0] : args) as unknown[];
  const options = (typeof first[0] === 'object' ? first[0] : { port: first[0], host: first[1] }) as { port: number; host?: string };
  if (!['localhost', '127.0.0.1', '::1'].includes(options.host ?? 'localhost') || Number(options.port) !== Number(process.env.UNIFI_AXI_TEST_PORT)) {
    appendFileSync(process.env.UNIFI_AXI_TEST_NETWORK_LOG!, 'network-attempt\n');
    throw new Error('Only the fake vendor listener is reachable');
  }
  return Reflect.apply(connect, this, args) as Socket;
} as typeof connect;
dgram.Socket.prototype.send = function () {
  appendFileSync(process.env.UNIFI_AXI_TEST_NETWORK_LOG!, 'network-attempt\n');
  throw new Error('Datagrams are unavailable');
};

// Faults live in the test preload, never in product flags or environment handling.
const fault = process.env.UNIFI_AXI_TEST_FAULT;
const tlsConnect = tls.connect;
let connections = 0;
tls.connect = ((...args: Parameters<typeof tlsConnect>) => {
  const socket = Reflect.apply(tlsConnect, tls, args) as ReturnType<typeof tlsConnect>;
  connections++;
  if (connections === Number(process.env.UNIFI_AXI_TEST_PEER_DRIFT)) {
    socket.prependOnceListener('secureConnect', () => Object.defineProperty(socket, 'remoteAddress', { value: '127.0.0.2' }));
  }
  return socket;
}) as typeof tlsConnect;
const mkdir = fs.mkdir;
fs.mkdir = (async (...args: Parameters<typeof mkdir>) => {
  const exclusiveClaim = /\/[a-f0-9]{64}\/[a-f0-9]{64}$/.test(String(args[0])) &&
    typeof args[1] === 'object' && args[1]?.recursive === false;
  if (exclusiveClaim && fault === 'before-claim') throw new Error('Synthetic persistence failure');
  const result = await Reflect.apply(mkdir, fs, args);
  if (exclusiveClaim && fault === 'after-claim') process.exit(99);
  return result;
}) as typeof mkdir;
const open = fs.open;
fs.open = async (...args: Parameters<typeof open>) => {
  const handle = await open(...args);
  if (typeof args[1] === 'number' && (args[1] & constants.O_DIRECTORY) !== 0) {
    const sync = handle.sync.bind(handle);
    handle.sync = async () => {
      if (fault === 'ancestor-sync' && String(args[0]) === dirname(process.env.UNIFI_AXI_WRITE_LOG!)) throw new Error('Synthetic ancestor sync failure');
      await sync();
      let text: string;
      try { text = await fs.readFile(join(String(args[0]), 'intent.json'), 'utf8'); }
      catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
      const record = JSON.parse(text) as { outcome: string };
      if ((fault === 'after-intent-sync' && record.outcome === 'not-sent') ||
          (fault === 'before-send' && record.outcome === 'unknown') ||
          (fault === 'after-ack' && record.outcome === 'accepted')) process.exit(99);
    };
  }
  return handle;
};
const request = https.request;
https.request = ((...args: Parameters<typeof request>) => {
  const call = Reflect.apply(request, https, args) as ReturnType<typeof request>;
  if (fault === 'after-possible-send' && call.method === 'POST') call.once('finish', () => process.exit(99));
  return call;
}) as typeof request;
syncBuiltinESMExports();
