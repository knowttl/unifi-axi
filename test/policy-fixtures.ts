export type Row = Record<string, unknown>;
export const site = '9361553d-e20d-45b8-a516-6948ab010011';
export const id = '8c850c83-1111-4111-8111-000000000001';
export const neighbourId = '8c850c83-1111-4111-8111-000000000002';
export const otherSite = '5925a212-9b6e-402b-a675-c658ab010022';

export function firewallBody(version: string): Row {
  return { name: 'Synthetic policy', enabled: true, loggingEnabled: false,
    action: { type: 'ALLOW', allowReturnTraffic: false }, source: { zoneId: id }, destination: { zoneId: neighbourId },
    ipProtocolScope: { ipVersion: 'IPV4_AND_IPV6' }, ...(version === '11.0.97' ? { reportFlowEnabled: false } : {}) };
}

export function firewallRecord(version: string, body = firewallBody(version)): Row {
  return { ...body, id, index: 0, metadata: { origin: 'USER_DEFINED' } };
}

export function firewallVariants(version: string): Row[] {
  const base = firewallBody(version);
  const port = { type: 'PORTS', matchOpposite: false, items: [
    { type: 'PORT_NUMBER', value: 443 }, { type: 'PORT_NUMBER_RANGE', start: 8000, stop: 8080 }] };
  const portReference = { type: 'TRAFFIC_MATCHING_LIST', matchOpposite: true, trafficMatchingListId: neighbourId };
  const filters: Row[] = [
    { type: 'IP_ADDRESS', ipAddressFilter: { type: 'IP_ADDRESSES', matchOpposite: false, items: [
      { type: 'IP_ADDRESS', value: '192.0.2.1' }, { type: 'SUBNET', value: '198.51.100.0/24' },
      { type: 'IP_ADDRESS_RANGE', start: '203.0.113.1', stop: '203.0.113.5' }] } },
    { type: 'IP_ADDRESS', ipAddressFilter: { type: 'TRAFFIC_MATCHING_LIST', matchOpposite: true, trafficMatchingListId: neighbourId } },
    { type: 'IPV6_IID', ipv6IidFilter: { ipv6Iid: '::1', matchOpposite: false } },
    { type: 'NETWORK', networkFilter: { matchOpposite: true, networkIds: [neighbourId] } },
    { type: 'PORT', portFilter: port }, { type: 'PORT', portFilter: portReference },
    { type: 'REGION', regionFilter: { regions: ['CA'] } },
    { type: 'SITE_TO_SITE_VPN_TUNNEL', siteToSiteVpnTunnelFilter: { siteToSiteVpnTunnelId: neighbourId } },
    { type: 'VPN_SERVER', vpnServerFilter: { matchOpposite: false, vpnServerIds: [neighbourId] } },
  ];
  const bodies: Row[] = [base, ...['BLOCK', 'REJECT'].map(type => ({ ...base, action: { type } }))];
  for (const side of ['source', 'destination']) {
    const extra = side === 'source' ? [{ type: 'MAC_ADDRESS', macAddressFilter: { macAddresses: ['02:00:00:00:00:01'] } }] : [
      { type: 'APPLICATION', applicationFilter: { applicationIds: [7] } },
      { type: 'APPLICATION_CATEGORY', applicationCategoryFilter: { applicationCategoryIds: [1] } },
      { type: 'DOMAIN', domainFilter: { type: 'DOMAINS', domains: ['example.invalid'] } },
    ];
    for (const trafficFilter of [...filters, ...extra]) bodies.push({ ...base,
      [side]: { zoneId: side === 'source' ? id : neighbourId, trafficFilter } });
  }
  for (const ipVersion of ['IPV4', 'IPV6', 'IPV4_AND_IPV6']) {
    bodies.push({ ...base, ipProtocolScope: { ipVersion } });
    for (const protocolFilter of [
      { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'tcp' } },
      { type: 'PRESET', preset: { name: 'TCP_UDP' } },
      { type: 'PROTOCOL_NUMBER', matchOpposite: true, protocolNumber: 17 },
      ...(ipVersion === 'IPV4' ? [{ type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'icmp', typenameFilter: 'ECHO_REQUEST' } }] : []),
      ...(ipVersion === 'IPV6' ? [{ type: 'NAMED_PROTOCOL', matchOpposite: true, protocol: { name: 'icmpv6', typenameFilter: 'ECHO_REPLY' } }] : []),
    ]) bodies.push({ ...base, ipProtocolScope: { ipVersion, protocolFilter } });
  }
  const timeFilter = { startTime: '09:00', stopTime: '17:00' };
  for (const schedule of [
    { mode: 'EVERY_DAY', timeFilter }, { mode: 'EVERY_WEEK', repeatOnDays: ['MONDAY'], timeFilter },
    { mode: 'ONE_TIME_ONLY', date: '2026-11-02', timeFilter },
    { mode: 'CUSTOM', repeatOnDays: ['FRIDAY'], startDate: '2026-11-02', stopDate: '2026-11-06', timeFilter },
  ]) bodies.push({ ...base, schedule, connectionStateFilter: ['NEW', 'ESTABLISHED'], ipsecFilter: 'MATCH_ENCRYPTED', description: 'Synthetic scheduled policy' });
  return bodies;
}

export const aclBodies: Row[] = [
  ...[
    { type: 'IP_ADDRESSES_OR_SUBNETS', ipAddressesOrSubnets: ['192.0.2.0/24'], portFilter: [443] },
    { type: 'NETWORKS', networkIds: [neighbourId], portFilter: [53] },
    { type: 'PORTS', portFilter: [80, 443] },
  ].map(endpoint => ({ type: 'IPV4', name: 'Synthetic IP ACL', enabled: true, action: 'ALLOW',
    sourceFilter: endpoint, destinationFilter: endpoint, protocolFilter: ['TCP', 'UDP'],
    enforcingDeviceFilter: { type: 'DEVICES', deviceIds: [neighbourId] } })),
  { type: 'MAC', name: 'Synthetic MAC ACL', enabled: false, action: 'BLOCK', networkIdFilter: neighbourId,
    sourceFilter: { type: 'MAC_ADDRESSES', macAddresses: ['02:00:00:00:00:01'], prefixLength: 48 },
    destinationFilter: { type: 'MAC_ADDRESSES', macAddresses: ['02:00:00:00:00:02'] } },
];
