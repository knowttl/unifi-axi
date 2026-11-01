import assert from 'node:assert/strict';
import { networkBodies } from './b4.ts';

const site = '9361553d-e20d-45b8-a516-6948ab010011';
const otherSite = '5925a212-9b6e-402b-a675-c658ab010022';
const id = '8c850c83-1111-4111-8111-000000000001';
const secondId = '8c850c83-1111-4111-8111-000000000002';
const metadata = { origin: 'USER_DEFINED' };
const device = { id, name: 'Lab switch', macAddress: '02:00:00:00:00:01', ipAddress: '192.0.2.5',
  model: 'USW', state: 'ONLINE', supported: true, firmwareUpdatable: false,
  features: ['switching'], interfaces: ['ports'] };
const client = { id, name: 'Lab client', type: 'WIRED', ipAddress: '192.0.2.10',
  macAddress: '02:00:00:00:00:10', uplinkDeviceId: secondId, connectedAt: '2026-10-30T12:00:00Z', access: { type: 'DEFAULT' } };
const network = { id, name: 'Lab network', management: 'UNMANAGED', enabled: true, vlanId: 10, default: false, metadata };
const families = [
  ['country list', '/countries', 'countries', { code: 'CA', name: 'Canada' }, { code: 'NZ', name: 'New Zealand' }],
  ['dpi application list', '/dpi/applications', 'applications', { id: 101, name: 'Lab application' }, { id: 102, name: 'Other application' }],
  ['dpi category list', '/dpi/categories', 'categories', { id: 10, name: 'Lab category' }, { id: 11, name: 'Other category' }],
  ['device pending list', '/pending-devices', 'pendingDevices',
    { ...Object.fromEntries(Object.entries(device).filter(([key]) => !['id', 'name', 'interfaces'].includes(key))), adoptionTargetSiteIds: [site] }],
  ['device-tag list', `/sites/${site}/device-tags`, 'deviceTags', { id, name: 'Lab tag', deviceIds: [secondId], metadata }],
  ['radius profile list', `/sites/${site}/radius/profiles`, 'radiusProfiles', { id, name: 'Lab RADIUS', metadata }],
  ['vpn server list', `/sites/${site}/vpn/servers`, 'vpnServers', { id, name: 'Lab VPN', type: 'WIREGUARD', enabled: true, metadata }],
  ['vpn site-to-site-tunnel list', `/sites/${site}/vpn/site-to-site-tunnels`, 'vpnTunnels', { id, name: 'Lab tunnel', type: 'IPSEC', metadata }],
  ['wan list', `/sites/${site}/wans`, 'wans', { id, name: 'Lab WAN' }],
  ['device list', `/sites/${site}/devices`, 'devices', device],
  ['client list', `/sites/${site}/clients`, 'clients', client],
  ['network list', `/sites/${site}/networks`, 'networks', network],
];

// Shared by the installed CLI and the real Artium client, against independent synthetic state.
export async function verifyInventory({ cli, seed }) {
  const rows = [];
  let version = '10.6.109';
  const scoped = words => [...words.split(' '), ...(words.startsWith('country') || words.startsWith('dpi') || words.startsWith('device pending') ? [] : ['--site', site])];
  const serve = handler => seed((request, response) => {
    const url = new URL(request.url, 'https://synthetic.invalid');
    if (url.pathname.endsWith('/info')) return { applicationVersion: version };
    return handler(url, response);
  });
  for (version of ['10.6.109', '11.0.97']) {
    // Preserve the published --full read surface admitted by the host fixture.
    for (const [args, key, expected] of [
      [['info', '--full'], 'information', { applicationVersion: version }],
      [['client', 'list', '--site', site, '--full'], 'clients', [client]],
    ]) {
      serve(url => {
        assert.equal(url.pathname, `/proxy/network/integration/v1/sites/${site}/clients`);
        return { offset: 0, limit: 25, count: 1, totalCount: 1, data: [client] };
      });
      assert.deepEqual((await cli(args))[key], expected);
    }
    for (const [command, path, key, first, next] of families) {
      if (version === '11.0.97' && command.startsWith('device ')) {
        serve(() => ({ offset: 0, limit: 25, count: 0, totalCount: 0, data: [] }));
        assert.equal((await cli(scoped(command), 1)).error.code, 'CONTRACT_CONFLICT');
        rows.push({ command, version, status: 'known-contract-conflict', conflict: 'CF-007' });
        continue;
      }
      const second = next ?? { ...first, ...(first.id ? { id: secondId } : {}),
        ...(first.macAddress ? { macAddress: '02:00:00:00:00:02' } : {}),
        ...(key === 'vpnTunnels' ? { metadata: { origin: 'DERIVED', source: 'SDWAN' } } : {}) };
      const records = [first, second];
      const filter = "name.ne('excluded')";
      serve(url => {
        assert.equal(url.pathname, `/proxy/network/integration/v1${path}`);
        assert.equal(url.searchParams.get('filter'), command === 'wan list' ? null : filter);
        const offset = Number(url.searchParams.get('offset'));
        const selected = records[offset];
        const data = ['vpnServers', 'vpnTunnels', 'wans'].includes(key) ?
          [{ ...selected, connectionConfiguration: { address: '192.0.2.99' }, ...(key === 'wans' ? { type: 'undocumented' } :
            selected.metadata.origin === 'USER_DEFINED' ? { metadata: { ...selected.metadata, source: 'unexpected' } } : {}) }] : [selected];
        return { offset, limit: 1, count: 1, totalCount: 2, data };
      });
      const result = await cli([...scoped(command), '--limit', '1', ...(command === 'wan list' ? [] : ['--filter', filter])]);
      assert.deepEqual(result[key], records);
      assert.deepEqual([result.count, result.totalCount, result.complete], [2, 2, true]);
      rows.push({ command, version, status: 'passed', direction: 'filtered-multi-page' });
      if (['device list', 'client list', 'network list'].includes(command)) {
        serve(() => ({ offset: 0, limit: 25, count: 0, totalCount: 0, data: [] }));
        const empty = await cli(scoped(command));
        assert.deepEqual([empty[key], empty.count, empty.totalCount, empty.complete], [[], 0, 0, true]);
      }
    }
    serve(() => ({ offset: 0, limit: 0, count: 0, totalCount: 2, data: [] }));
    assert.equal((await cli(['country', 'list', '--limit', '0'])).complete, false);
    serve(() => ({ offset: 0, limit: 25, count: 0, data: [] }));
    assert.equal((await cli(['country', 'list'], 1)).error.code, 'RESPONSE_INVALID');

    const details = { ...device, configurationId: 'synthetic-config', features: { switching: { lags: [] } }, interfaces: { ports: [
      { idx: 1, state: 'UP', connector: 'RJ45', maxSpeedMbps: 1000, speedMbps: 1000,
        poe: { standard: '802.3at', type: 2, enabled: true, state: 'UP' } },
    ] } };
    const statistics = { uptimeSec: 123, interfaces: {}, uplink: { txRateBps: 100, rxRateBps: 200 } };
    serve(url => {
      const path = `/proxy/network/integration/v1/sites/${site}/devices/${id}`;
      assert.ok([path, `${path}/statistics/latest`].includes(url.pathname));
      return url.pathname.endsWith('/statistics/latest') ? statistics : details;
    });
    if (version === '11.0.97') {
      for (const words of [['device', 'show'], ['device', 'statistics', 'latest']]) {
        assert.equal((await cli([...words, '--site', site, '--device-id', id], 1)).error.code, 'CONTRACT_CONFLICT');
      }
    } else {
      const selected = await cli(['device', 'show', '--site', site, '--device-id', id]);
      assert.deepEqual(selected.device, details);
      assert.equal(selected.device.interfaces.ports[0].poe.type, 2);
      assert.deepEqual((await cli(['device', 'statistics', 'latest', '--site', site, '--device-id', id])).statistics, statistics);
      for (const bad of ['2', {}]) {
        serve(() => ({ ...details, interfaces: { ports: [{ ...details.interfaces.ports[0], poe: { ...details.interfaces.ports[0].poe, type: bad } }] } }));
        const error = (await cli(['device', 'show', '--site', site, '--device-id', id], 1)).error;
        assert.equal(error.code, 'RESPONSE_INVALID');
        assert.match(error.message, /\/interfaces\/ports\/0\/poe\/type/);
      }
    }
    serve(url => {
      assert.equal(url.pathname, `/proxy/network/integration/v1/sites/${site}/clients/${id}`);
      return client;
    });
    // The fake returns the documented HTTP failure for both absent and cross-site targets.
    assert.deepEqual((await cli(['client', 'show', '--site', site, '--client-id', id])).client, client);
    serve((url, response) => {
      assert.ok(url.pathname.includes(otherSite) || url.pathname.endsWith(secondId));
      response.writeHead(404); response.end();
    });
    for (const [selectedSite, selectedId] of [[site, secondId], [otherSite, id]]) {
      assert.equal((await cli(['client', 'show', '--site', selectedSite, '--client-id', selectedId], 1)).error.code, 'UPSTREAM_ERROR');
    }

    const variants = [
      network,
      { ...network, management: 'SWITCH', deviceId: secondId, isolationEnabled: false, cellularBackupEnabled: false,
        ipv4Configuration: { autoScaleEnabled: false, hostIpAddress: '192.0.2.1', prefixLength: 24 } },
      { ...network, management: 'GATEWAY', isolationEnabled: false, cellularBackupEnabled: false,
        internetAccessEnabled: true, mdnsForwardingEnabled: false, ipv4Configuration: { autoScaleEnabled: false, hostIpAddress: '192.0.2.1', prefixLength: 24 } },
    ];
    for (const variant of variants) {
      serve(() => ({ ...variant, dhcpGuarding: null }));
      assert.deepEqual((await cli(['network', 'show', '--site', site, '--network-id', id])).network, { ...variant, dhcpGuarding: null });
    }
    for (const [index, body] of networkBodies.entries()) {
      const record = { ...body, id, default: false,
        metadata: { origin: ['USER_DEFINED', 'SYSTEM_DEFINED', 'ORCHESTRATED'][index % 3] } };
      const overview = Object.fromEntries(Object.entries(record).filter(([key]) =>
        ['id', 'name', 'management', 'enabled', 'default', 'vlanId', 'metadata', 'deviceId', 'zoneId'].includes(key)));
      serve(url => url.pathname.endsWith(`/${id}`) ? record :
        { offset: 0, limit: 25, count: 1, totalCount: 1, data: [overview] });
      assert.deepEqual((await cli(['network', 'list', '--site', site])).networks, [overview]);
      assert.deepEqual((await cli(['network', 'show', '--site', site, '--network-id', id])).network, record);
      rows.push({ task: 'B4.11', command: 'network list/show', version, variant: index,
        status: 'passed', direction: 'public-managed-network-variants' });
    }
    for (const type of ['WIRED', 'WIRELESS', 'VPN', 'TELEPORT']) {
      for (const access of type === 'WIRED' || type === 'WIRELESS' ?
        [{ type: 'DEFAULT' }, { type: 'GUEST', authorized: false }, { type: 'GUEST', authorized: true,
          authorization: { authorizationMethod: 'API', authorizedAt: '2026-10-30T12:00:00Z',
            expiresAt: '2026-10-30T13:00:00Z', dataUsageLimitMBytes: 256, rxRateLimitKbps: 1000, txRateLimitKbps: 500 } }] : [{ type: 'DEFAULT' }]) {
        const record = { id, name: 'Synthetic client', type, access, connectedAt: client.connectedAt, ipAddress: client.ipAddress,
          ...(['WIRED', 'WIRELESS'].includes(type) ? { macAddress: client.macAddress, uplinkDeviceId: secondId } : {}) };
        const { authorization, ...overviewAccess } = access;
        const overview = { ...record, access: overviewAccess };
        serve(url => url.pathname.endsWith(`/${id}`) ? record :
          { offset: 0, limit: 25, count: 1, totalCount: 1, data: [overview] });
        assert.deepEqual((await cli(['client', 'list', '--site', site])).clients, [overview]);
        assert.deepEqual((await cli(['client', 'show', '--site', site, '--client-id', id])).client,
          { ...record, access: { ...overviewAccess, ...(authorization ? { authorization: '[REDACTED]' } : {}) } });
        rows.push({ task: 'B4.11', command: 'client list/show', version, type, access,
          status: 'passed', direction: 'public-client-type-and-access-variants' });
      }
    }
    for (const [command, key, types] of [
      ['vpn server list', 'vpnServers', ['L2TP', 'OPENVPN', 'PPTP', 'UID', 'WIREGUARD']],
      ['vpn site-to-site-tunnel list', 'vpnTunnels', ['IPSEC', 'OPENVPN', 'WIREGUARD']],
    ]) {
      for (const type of types) {
        for (const origin of ['USER_DEFINED', 'DERIVED']) {
          const record = { id, name: 'Synthetic VPN', type, ...(key === 'vpnServers' ? { enabled: true } : {}),
            metadata: { origin, ...(key === 'vpnTunnels' && origin === 'DERIVED' ? { source: 'SDWAN' } : {}) } };
          serve(() => ({ offset: 0, limit: 25, count: 1, totalCount: 1,
            data: [{ ...record, connectionConfiguration: { address: '192.0.2.99' } }] }));
          assert.deepEqual((await cli(scoped(command)))[key], [record]);
          rows.push({ task: 'B4.11', command, version, type, origin,
            status: 'passed', direction: 'public-vpn-overview-variants' });
        }
      }
    }
    for (const [command, key, origins] of [
      ['device-tag list', 'deviceTags', ['USER_DEFINED', 'ORCHESTRATED']],
      ['radius profile list', 'radiusProfiles', ['USER_DEFINED', 'SYSTEM_DEFINED', 'DERIVED']],
    ]) {
      for (const origin of origins) {
        const record = { id, name: 'Synthetic metadata variant', metadata: { origin },
          ...(key === 'deviceTags' ? { deviceIds: [secondId] } : {}) };
        serve(() => ({ offset: 0, limit: 25, count: 1, totalCount: 1, data: [record] }));
        assert.deepEqual((await cli(scoped(command)))[key], [record]);
        rows.push({ task: 'B4.11', command, version, origin, status: 'passed', direction: 'public-metadata-variants' });
      }
    }
    const references = { referenceResources: [{ resourceType: 'CLIENT', referenceCount: 2,
      references: [{ referenceId: id }, { referenceId: secondId }] }] };
    serve(url => url.pathname.endsWith('/references') ? references : network);
    const result = await cli(['network', 'references', '--site', site, '--network-id', id]);
    assert.deepEqual(result, { api: { applicationVersion: version, contract: version, status: 'verified', writesAvailable: false },
      selectedSite: site, network: { id, name: network.name }, references });
    serve(() => ({ ...network, metadata: null }));
    assert.equal((await cli(['network', 'show', '--site', site, '--network-id', id], 1)).error.code, 'RESPONSE_INVALID');
    serve(() => ({ ...variants[2], ipv6Configuration: null }));
    const error = (await cli(['network', 'show', '--site', site, '--network-id', id], 1)).error;
    assert.equal(error.code, 'RESPONSE_INVALID');
    assert.match(error.message, /\/ipv6Configuration/);
  }
  return rows;
}
