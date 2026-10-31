import { appendFileSync } from 'node:fs';
import { Socket } from 'node:net';
import dgram from 'node:dgram';
import { syncBuiltinESMExports } from 'node:module';

// B1.1 has no network capability. Record even a caught attempt at the external boundary.
function denied() {
  appendFileSync(process.env.UNIFI_AXI_TEST_NETWORK_LOG, 'network-attempt\n');
  throw new Error('Offline verification forbids network access');
}

Socket.prototype.connect = denied;
dgram.Socket.prototype.send = denied;
syncBuiltinESMExports();
