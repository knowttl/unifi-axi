import { Socket } from 'node:net';
import dgram from 'node:dgram';
import { syncBuiltinESMExports } from 'node:module';

// Install at the socket boundary in the host, client and packaged child.
// Only the two task-owned loopback listeners are reachable, including after redirects.
export function guardEgress(ports, denied) {
  const connect = Socket.prototype.connect;
  Socket.prototype.connect = function (...args) {
    const first = Array.isArray(args[0]) ? args[0] : args;
    const options = typeof first[0] === 'object' ? first[0] : { port: first[0], host: typeof first[1] === 'string' ? first[1] : 'localhost' };
    if (!['localhost', '127.0.0.1', '::1'].includes(options.host ?? 'localhost') || !ports.includes(Number(options.port))) {
      denied();
      throw new Error('Synthetic verification forbids non-fixture egress');
    }
    return Reflect.apply(connect, this, args);
  };
  dgram.Socket.prototype.send = function () {
    denied();
    throw new Error('Synthetic verification forbids datagrams');
  };
  syncBuiltinESMExports();
}
