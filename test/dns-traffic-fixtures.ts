import type { Row } from './policy-fixtures.ts';

export const dnsTrafficCases: Record<string, string[]> = {
  A_RECORD: ['VAR-026', 'VAR-041'], AAAA_RECORD: ['VAR-025', 'VAR-040'],
  CNAME_RECORD: ['VAR-027', 'VAR-042'], FORWARD_DOMAIN: ['VAR-028', 'VAR-043'],
  MX_RECORD: ['VAR-029', 'VAR-044'], SRV_RECORD: ['VAR-030', 'VAR-045'], TXT_RECORD: ['VAR-031', 'VAR-046'],
  IPV4_ADDRESSES: ['VAR-035', 'VAR-230', 'VAR-195', 'VAR-196', 'VAR-197'],
  IPV6_ADDRESSES: ['VAR-036', 'VAR-231', 'VAR-198', 'VAR-199'],
  PORTS: ['VAR-037', 'VAR-232', 'VAR-219', 'VAR-220'],
};

export const dnsBodies: Row[] = [
  { type: 'A_RECORD', ipv4Address: '192.0.2.10', ttlSeconds: 300 },
  { type: 'AAAA_RECORD', ipv6Address: '2001:db8::10', ttlSeconds: 600 },
  { type: 'CNAME_RECORD', targetDomain: 'target.example', ttlSeconds: 3600 },
  { type: 'FORWARD_DOMAIN', ipAddress: '192.0.2.53' },
  { type: 'MX_RECORD', mailServerDomain: 'mail.example', priority: 10 },
  { type: 'SRV_RECORD', port: 443, priority: 1, protocol: '_tcp', serverDomain: 'service.example', service: '_https', weight: 5 },
  { type: 'TXT_RECORD', text: 'synthetic verification' },
].map((fields, index) => ({ enabled: true, domain: `lab${index}.example`, ...fields }));

export const trafficBodies: Row[] = [
  { name: 'Lab IPv4', type: 'IPV4_ADDRESSES', items: [
    { type: 'IP_ADDRESS', value: '192.0.2.10' }, { type: 'SUBNET', value: '198.51.100.0/24' },
    { type: 'IP_ADDRESS_RANGE', start: '203.0.113.1', stop: '203.0.113.10' },
    { type: 'SUBNET', value: '0.0.0.0/0' }, { type: 'SUBNET', value: '192.0.2.1/32' },
    { type: 'IP_ADDRESS_RANGE', start: '192.0.2.2', stop: '192.0.2.10' },
    { type: 'IP_ADDRESS_RANGE', start: '192.0.2.1', stop: '192.0.2.1' }] },
  { name: 'Lab IPv6', type: 'IPV6_ADDRESSES', items: [
    { type: 'IP_ADDRESS', value: '2001:db8::1' }, { type: 'SUBNET', value: '2001:db8:1::/64' },
    { type: 'SUBNET', value: '::/0' }, { type: 'SUBNET', value: '2001:db8::1/128' }] },
  { name: 'Lab ports', type: 'PORTS', items: [
    { type: 'PORT_NUMBER', value: 443 }, { type: 'PORT_NUMBER_RANGE', start: 8000, stop: 8080 },
    { type: 'PORT_NUMBER', value: 1 }, { type: 'PORT_NUMBER', value: 65535 },
    { type: 'PORT_NUMBER_RANGE', start: 1, stop: 65535 }, { type: 'PORT_NUMBER_RANGE', start: 443, stop: 443 }] },
];
