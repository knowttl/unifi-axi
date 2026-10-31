import assert from 'node:assert/strict';

const site = '9361553d-e20d-45b8-a516-6948ab010011';
const otherSite = '5925a212-9b6e-402b-a675-c658ab010022';
const id = '8c850c83-1111-4111-8111-000000000001';
const secondId = '8c850c83-1111-4111-8111-000000000002';
const metadata = { origin: 'USER_DEFINED' };
const endpointFilters = [
  { type: 'IP_ADDRESSES_OR_SUBNETS', ipAddressesOrSubnets: ['192.0.2.0/24'], portFilter: [443] },
  { type: 'NETWORKS', networkIds: [secondId], portFilter: [53] },
  { type: 'PORTS', portFilter: [80, 443] },
];
const aclRules = [
  ...endpointFilters.map((sourceFilter, index) => ({ id: `8c850c83-1111-4111-8111-00000000000${index + 1}`,
    type: 'IPV4', name: `Lab IP rule ${index}`, index, enabled: true, action: index === 1 ? 'BLOCK' : 'ALLOW', metadata,
    sourceFilter, destinationFilter: endpointFilters[(index + 1) % 3], protocolFilter: ['TCP', 'UDP'],
    enforcingDeviceFilter: { type: 'DEVICES', deviceIds: [secondId] } })),
  { id: '8c850c83-1111-4111-8111-000000000004', type: 'MAC', name: 'Lab MAC rule', index: 3,
    enabled: false, action: 'BLOCK', metadata, networkIdFilter: secondId,
    sourceFilter: { type: 'MAC_ADDRESSES', macAddresses: ['02:00:00:00:00:01'], prefixLength: 48 },
    destinationFilter: { type: 'MAC_ADDRESSES', macAddresses: ['02:00:00:00:00:02'] } },
];
const dnsPolicies = [
  ['A_RECORD', { ipv4Address: '192.0.2.10', ttlSeconds: 300 }],
  ['AAAA_RECORD', { ipv6Address: '2001:db8::10', ttlSeconds: 600 }],
  ['CNAME_RECORD', { targetDomain: 'target.example', ttlSeconds: 3600 }],
  ['FORWARD_DOMAIN', { ipAddress: '192.0.2.53' }],
  ['MX_RECORD', { mailServerDomain: 'mail.example', priority: 10 }],
  ['SRV_RECORD', { port: 443, priority: 1, protocol: 'tcp', serverDomain: 'service.example', service: 'https', weight: 5 }],
  ['TXT_RECORD', { text: 'synthetic verification' }],
].map(([type, fields], index) => ({ id: `8c850c83-1111-4111-8111-00000000000${index + 1}`,
  enabled: true, metadata, type, domain: `lab${index}.example`, ...fields }));
const trafficLists = [
  { id, name: 'Lab IPv4', type: 'IPV4_ADDRESSES', items: [
    { type: 'IP_ADDRESS', value: '192.0.2.10' }, { type: 'SUBNET', value: '198.51.100.0/24' },
    { type: 'IP_ADDRESS_RANGE', start: '203.0.113.1', stop: '203.0.113.10' }] },
  { id: secondId, name: 'Lab IPv6', type: 'IPV6_ADDRESSES', items: [
    { type: 'IP_ADDRESS', value: '2001:db8::1' }, { type: 'SUBNET', value: '2001:db8:1::/64' }] },
  { id: '8c850c83-1111-4111-8111-000000000003', name: 'Lab ports', type: 'PORTS', items: [
    { type: 'PORT_NUMBER', value: 443 }, { type: 'PORT_NUMBER_RANGE', start: 8000, stop: 8080 }] },
];
const members = [{ deviceId: id, portIdxs: [1, 2] }, { deviceId: secondId, portIdxs: [3, 4] }];
const stackMembers = [{ unitId: 1, unitMacAddress: '02:00:00:00:00:01', portIdxs: [1, 2] }];
const lags = [
  { id, metadata, type: 'LOCAL', members },
  { id: secondId, metadata, type: 'MULTI_CHASSIS', mcLagDomainId: id, members },
  { id: '8c850c83-1111-4111-8111-000000000003', metadata, type: 'SWITCH_STACK', switchStackId: id, members: stackMembers },
];
const mcLagDomains = [{ id, name: 'Lab MC-LAG', metadata, peers: [
  { deviceId: id, linkPortIdxs: [47, 48], role: 'TOP' },
  { deviceId: secondId, linkPortIdxs: [47, 48], role: 'BOTTOM' }], lags: [{ id: secondId, metadata, members }] }];
const switchStacks = [{ id, name: 'Lab stack', metadata, deviceId: secondId, units: [
  { id: 1, macAddress: '02:00:00:00:00:01', order: 0, role: 'ACTIVE_CONTROLLER' },
  { id: 2, macAddress: '02:00:00:00:00:02', order: 1, role: 'BACKUP_CONTROLLER' },
  { id: 3, macAddress: '02:00:00:00:00:03', order: 2, role: 'MEMBER' }],
lags: [{ id: secondId, metadata, members: stackMembers }] }];
const voucher = { id, name: 'Lab voucher', code: 'SYNTHETIC-VOUCHER-48291', authorizedGuestCount: 1,
  authorizedGuestLimit: 2, createdAt: '2026-10-30T12:00:00Z', expired: false, timeLimitMinutes: 60,
  dataUsageLimitMBytes: 100, rxRateLimitKbps: 1000, txRateLimitKbps: 500 };
const wifi = { id, name: 'Lab Wi-Fi', type: 'STANDARD', metadata, enabled: true,
  broadcastingFrequenciesGHz: [2.4, 5], securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'SYNTHETIC-WIFI-48291' } };

// Independent synthetic state, exercised through both installed and hosted public clients.
export async function verifyPolicies({ cli, seed }) {
  const rows = [];
  for (const version of ['10.6.109', '11.0.97']) {
    const serve = handler => seed((request, response) => {
      const url = new URL(request.url, 'https://synthetic.invalid');
      if (url.pathname.endsWith('/info')) return { applicationVersion: version };
      assert.equal(request.method, 'GET');
      return handler(url, response);
    });
    const run = (command, flags = [], code = 0) => cli([...command.split(' '), '--site', site, ...flags], code);
    for (const [command, path, key, flag, records] of [
      ['acl-rule', 'acl-rules', 'aclRules', 'acl-rule-id', aclRules],
      ['dns policy', 'dns/policies', 'dnsPolicies', 'dns-policy-id', dnsPolicies],
      ['traffic-list', 'traffic-matching-lists', 'trafficLists', 'traffic-matching-list-id', trafficLists],
      ['firewall zone', 'firewall/zones', 'firewallZones', 'firewall-zone-id', [
        { id, name: 'Lab source zone', metadata, networkIds: [id, secondId] },
        { id: secondId, name: 'Lab destination zone', metadata, networkIds: [] }]],
      ['switching lag', 'switching/lags', 'lags', 'lag-id', lags],
      ['switching mc-lag-domain', 'switching/mc-lag-domains', 'mcLagDomains', 'mc-lag-domain-id', mcLagDomains],
      ['switching switch-stack', 'switching/switch-stacks', 'switchStacks', 'switch-stack-id', switchStacks],
    ]) {
      const base = `/proxy/network/integration/v1/sites/${site}/${path}`;
      const excluded = { ...records[0], id: '8c850c83-1111-4111-8111-000000000009', name: 'excluded' };
      const state = [...records, excluded];
      serve((url, response) => {
        if (url.pathname === base) {
          const filter = url.searchParams.get('filter');
          assert.equal(filter, "name.ne('excluded')");
          assert.equal(url.searchParams.get('limit'), '1');
          const selected = state.filter(row => row.name !== 'excluded');
          const offset = Number(url.searchParams.get('offset'));
          const data = selected.slice(offset, offset + 1);
          return { offset, limit: 1, count: data.length, totalCount: selected.length, data };
        }
        const selected = state.find(row => url.pathname === `${base}/${row.id}`);
        if (selected) return selected;
        response.writeHead(404); response.end();
      });
      const result = await run(`${command} list`, ['--limit', '1', '--filter', "name.ne('excluded')"]);
      assert.deepEqual(result[key], records);
      assert.deepEqual([result.count, result.totalCount, result.complete], [records.length, records.length, true]);
      const detailKey = { aclRules: 'aclRule', dnsPolicies: 'dnsPolicy', trafficLists: 'trafficList',
        firewallZones: 'firewallZone', lags: 'lag', mcLagDomains: 'mcLagDomain', switchStacks: 'switchStack' }[key];
      for (const record of records) assert.deepEqual((await run(`${command} show`, [`--${flag}`, record.id]))[detailKey], record);
      assert.equal((await cli([...`${command} show`.split(' '), '--site', otherSite, `--${flag}`, id], 1)).error.code, 'UPSTREAM_ERROR');
      if (command.startsWith('switching')) {
        serve(() => ({ offset: 0, limit: 25, count: 0, totalCount: 0, data: [] }));
        assert.deepEqual((await run(`${command} list`))[key], []);
        serve((url, response) => { response.writeHead(404); response.end(); });
        assert.equal((await run(`${command} show`, [`--${flag}`, id], 1)).error.code, 'UPSTREAM_ERROR');
      }
      rows.push({ command, version, status: 'passed', direction: 'filtered-list-and-details' });
    }
    const orderedAclRuleIds = [aclRules[3].id, aclRules[0].id, aclRules[2].id, aclRules[1].id];
    serve(url => {
      assert.equal(url.pathname, `/proxy/network/integration/v1/sites/${site}/acl-rules/ordering`);
      return { orderedAclRuleIds };
    });
    assert.deepEqual((await run('acl-rule order show')).aclRuleOrder, { orderedAclRuleIds });
    serve(() => ({ ...aclRules[0], sourceFilter: { type: 'PORTS', portFilter: ['443'] } }));
    assert.equal((await run('acl-rule show', ['--acl-rule-id', id], 1)).error.code, 'RESPONSE_INVALID');
    serve(() => ({ ...dnsPolicies[0], type: 'UNKNOWN' }));
    assert.equal((await run('dns policy show', ['--dns-policy-id', id], 1)).error.code, 'RESPONSE_INVALID');
    serve(() => ({ ...trafficLists[0], id: secondId }));
    assert.equal((await run('traffic-list show', ['--traffic-matching-list-id', id], 1)).error.code, 'RESPONSE_INVALID');

    const orders = { [id]: { beforeSystemDefined: [id], afterSystemDefined: [secondId] },
      [secondId]: { beforeSystemDefined: [], afterSystemDefined: [secondId, id] } };
    serve(url => {
      assert.equal(url.pathname, `/proxy/network/integration/v1/sites/${site}/firewall/policies/ordering`);
      assert.equal(url.searchParams.get('destinationFirewallZoneId'), secondId);
      return { orderedFirewallPolicyIds: orders[url.searchParams.get('sourceFirewallZoneId')] };
    });
    for (const source of [id, secondId]) assert.deepEqual((await run('firewall policy order show',
      ['--source-firewall-zone-id', source, '--destination-firewall-zone-id', secondId])).firewallPolicyOrder,
    { orderedFirewallPolicyIds: orders[source] });
    // Named protocol source conflicts are reachable even for an empty policy page.
    serve(() => ({ offset: 0, limit: 25, count: 0, totalCount: 0, data: [] }));
    const firewallConflictIds = version === '10.6.109' ? ['CF-002', 'CF-003', 'CF-004'] : ['CF-008', 'CF-009', 'CF-010'];
    const firewallConflicts = ['IPv4', 'IPv4 and IPv6', 'IPv6'].map((protocol, index) =>
      `${firewallConflictIds[index]} #/components/schemas/Firewall policy ${protocol} named protocol/properties/name`);
    for (const [command, flags] of [['firewall policy list', []], ['firewall policy show', ['--firewall-policy-id', id]]]) {
      assert.deepEqual((await run(command, flags, 1)).error, { code: 'CONTRACT_CONFLICT',
        message: `Response validation for ${version} blocked by ${firewallConflicts.join(', ')}.` });
    }

    serve(url => url.pathname.endsWith(`/${id}`) ? voucher :
      { offset: 0, limit: 100, count: 1, totalCount: 1, data: [voucher] });
    const expectedVoucher = { ...voucher, code: '[REDACTED]' };
    assert.deepEqual((await run('hotspot voucher list')).vouchers, [expectedVoucher]);
    assert.deepEqual((await run('hotspot voucher show', ['--voucher-id', id])).voucher, expectedVoucher);
    serve(() => ({ ...voucher, expired: 'false' }));
    assert.equal((await run('hotspot voucher show', ['--voucher-id', id], 1)).error.code, 'RESPONSE_INVALID');
    serve(() => ({ offset: 0, limit: 25, count: 1, totalCount: 1, data: [wifi] }));
    assert.deepEqual((await run('wifi broadcast list')).wifiBroadcasts,
      [{ ...wifi, securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: '[REDACTED]' } }]);
    const wifiConflictIds = version === '10.6.109' ? ['CF-005', 'CF-006'] : ['CF-011', 'CF-012'];
    const wifiConflicts = ['2.4', '5'].map((frequency, index) =>
      `${wifiConflictIds[index]} #/components/schemas/IntegrationWifiBasicDataRateConfigurationDto/properties/${frequency}`);
    for (const record of [wifi, { ...wifi, basicDataRateKbpsByFrequencyGHz: { '2.4': 'invalid' } }]) {
      serve(() => record);
      assert.deepEqual((await run('wifi broadcast show', ['--wifi-broadcast-id', id], 1)).error, { code: 'CONTRACT_CONFLICT',
        message: `Response validation for ${version} blocked by ${wifiConflicts.join(', ')}.` });
    }
    rows.push({ command: 'firewall policy and wifi broadcast show', version, status: 'known-contract-conflict' },
      { command: 'hotspot voucher and wifi broadcast list', version, status: 'passed', direction: 'redacted' });
  }
  return rows;
}
