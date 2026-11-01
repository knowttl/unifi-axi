import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { VariantCoverage, obligations, type Exchange } from './variant-coverage.ts';
import { protocolVariants } from './protocol-variants.ts';
import { firewallBody, firewallRecord, id, site } from './policy-fixtures.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = `/proxy/network/integration/v1/sites/${site}/firewall/policies`;
const scope = { ipVersion: 'IPV4_AND_IPV6', protocolFilter: { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'DCCP' } } };

for (const version of ['10.6.109', '11.0.97']) {
  test(`DCCP is observed in every firewall operation position on ${version}`, () => {
    const coverage = new VariantCoverage('synthetic-test-key', root);
    const info: Exchange = { method: 'GET', path: '/proxy/network/integration/v1/info', request: '',
      response: JSON.stringify({ applicationVersion: version }), status: 200 };
    const body = { ...firewallBody(version), ipProtocolScope: scope };
    const emitted = { ...body, ipProtocolScope: { ...scope, protocolFilter: { ...scope.protocolFilter, protocol: { name: 'dccp' } } } };
    const record = firewallRecord(version, body);
    coverage.observe(['firewall', 'policy', 'list'], { firewallPolicies: [record], offset: 0, count: 1, totalCount: 1, complete: true },
      [info, { method: 'GET', path: `${base}?offset=0&limit=25`, request: '',
        response: JSON.stringify({ data: [record], offset: 0, limit: 25, count: 1, totalCount: 1 }), status: 200 }]);
    coverage.observe(['firewall', 'policy', 'show'], { firewallPolicy: record },
      [info, { method: 'GET', path: `${base}/${id}`, request: '', response: JSON.stringify(record), status: 200 }]);
    coverage.observe(['firewall', 'policy', 'create'], { preview: { body: emitted } }, [info]);
    coverage.observe(['firewall', 'policy', 'create', '--execute'], { write: { operation: 'OP-031', outcome: 'verified', target: id } },
      [info, { method: 'POST', path: base, request: JSON.stringify(emitted), response: JSON.stringify(record), status: 201 }]);
    coverage.observe(['firewall', 'policy', 'update'], { preview: { body: emitted } }, [info]);
    coverage.observe(['firewall', 'policy', 'update', '--execute'], { write: { operation: 'OP-037', outcome: 'verified', target: id } },
      [info, { method: 'PUT', path: `${base}/${id}`, request: JSON.stringify(emitted), response: JSON.stringify(record), status: 200 }]);
    coverage.observe(['firewall', 'policy', 'patch', '--execute'], { write: { operation: 'OP-036', outcome: 'verified', target: id } },
      [info, { method: 'PATCH', path: `${base}/${id}`, request: JSON.stringify({ loggingEnabled: true }), response: JSON.stringify(record), status: 200 }]);
    assert.equal(coverage.rows().filter(row => row.case === 'VAR-054' && row.version === version && row.status === 'passed').length, 7);
  });

  test(`protocol scenarios include the ledger DCCP selection on ${version}`, () => {
    assert.ok(protocolVariants(version).some(variant => variant.ipVersion === 'IPV4_AND_IPV6' && variant.name === 'DCCP'));
  });
}

for (const [name, wireScope, publishedScope] of [
  ['wrong enclosing IP scope', { ...scope, ipVersion: 'IPV4' }, { ...scope, ipVersion: 'IPV4' }],
  ['public output drops DCCP', scope, { ipVersion: 'IPV4_AND_IPV6' }],
] as const) {
  test(`${name} cannot satisfy VAR-054`, () => {
    const coverage = new VariantCoverage('synthetic-test-key', root);
    const wire = firewallRecord('10.6.109', { ...firewallBody('10.6.109'), ipProtocolScope: wireScope });
    const published = { ...wire, ipProtocolScope: publishedScope };
    coverage.observe(['firewall', 'policy', 'show'], { firewallPolicy: published }, [
      { method: 'GET', path: '/proxy/network/integration/v1/info', request: '', response: '{"applicationVersion":"10.6.109"}', status: 200 },
      { method: 'GET', path: `${base}/${id}`, request: '', response: JSON.stringify(wire), status: 200 },
    ]);
    assert.equal(coverage.rows().find(row => row.case === 'VAR-054' && row.version === '10.6.109' && row.operation === 'OP-035')?.status, 'pending-obligation');
  });
}

test('every unobserved ledger position carries a pending reason', () => {
  const rows = new VariantCoverage('synthetic-test-key', root).rows();
  const expected = obligations.cases.reduce((count, variant) => count + variant.versions.length * variant.positions.length, 0);
  assert.equal(rows.length, expected);
  assert.equal(new Set(rows.map(row => row.case)).size, 1251);
  assert.equal(rows.filter(row => row.status === 'pending-obligation' && row.reason).length, expected);
});
