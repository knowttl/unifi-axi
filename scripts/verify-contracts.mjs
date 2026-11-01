import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { compileContract, contractValidator, contractConflicts, validateResponse } from '../dist/validation.js';
import fixtures from '../test/fixtures/contracts.json' with { type: 'json' };
import ledger from '../src/normalization-ledger.json' with { type: 'json' };

const args = process.argv.slice(2).filter(arg => arg !== '--');
assert.ok(args.length === 0 || (args.length === 2 && args[0] === '--task' && args[1] === 'B2.1'));
const canonical = value => value && typeof value === 'object'
  ? Array.isArray(value) ? value.map(canonical) : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const rows = [];
for (const version of ['10.6.109', '11.0.97']) {
  const validator = contractValidator(version);
  for (const fixture of fixtures.filter(fixture => fixture.version === version)) {
    const before = structuredClone(fixture.value);
    assert.deepEqual(validator.validate(fixture.pointer, fixture.value), [], fixture.id);
    assert.deepEqual(fixture.value, before, 'Validation preserves payloads');
    const missing = structuredClone(fixture.value);
    delete missing.name;
    assert.notDeepEqual(validator.validate(fixture.pointer, missing), [], 'Required field removed');
    if (fixture.pointer.endsWith('/ACL rule')) {
      assert.notDeepEqual(validator.validate(fixture.pointer, { ...fixture.value, type: 'UNMAPPED' }), []);
      assert.deepEqual(validator.validate(fixture.pointer, { ...fixture.value, vendorAdded: false }), [], 'Additional fields remain permitted');
    } else {
      const added = { ...fixture.value, reportFlowEnabled: false };
      assert.deepEqual(validator.validate(fixture.pointer, added), []);
      delete added.reportFlowEnabled;
      assert.equal(validator.validate(fixture.pointer, added).length === 0, version === '10.6.109', 'Only v11 requires reportFlowEnabled');
    }
  }
  const radio = '#/components/schemas/Wireless radio overview/properties/frequencyGHz';
  assert.equal(validator.validate(radio, 0.9).length === 0, version === '11.0.97');
  assert.notDeepEqual(validator.validate(radio, '0.9'), []);
  const poe = '#/components/schemas/Port PoE overview/properties/type';
  const poeResolution = ledger.resolutions.find(rule => rule.id === 'CF-001');
  for (const value of poeResolution.positive) assert.equal(validator.validate(poe, value).length === 0, version === '10.6.109');
  for (const value of poeResolution.negative) assert.notDeepEqual(validator.validate(poe, value), []);
  const source = JSON.parse(readFileSync(new URL(`../evidence/sources/network-${version}-openapi.json`, import.meta.url)));
  for (const rule of [...ledger.resolutions, ...ledger.nullRequests].filter(rule => rule.version === version)) {
    let field = source;
    for (const part of rule.pointer.slice(2).split('/')) field = field[part.replaceAll('~1', '/').replaceAll('~0', '~')];
    assert.equal(createHash('sha256').update(JSON.stringify(canonical(field))).digest('hex'), rule.fieldHash);
    assert.equal(createHash('sha256').update(readFileSync(new URL(`../evidence/sources/network-${version}-openapi.json`, import.meta.url))).digest('hex'), rule.sourceHash);
    for (const value of rule.positive) assert.deepEqual(validator.validate(rule.pointer, value), [], rule.id);
    for (const value of rule.negative) assert.notDeepEqual(validator.validate(rule.pointer, value), [], rule.id);
  }
  const conflicts = contractConflicts(version);
  assert.equal(conflicts.length, 96, 'All six structural and ninety nullable conflicts per version');
  for (const conflict of conflicts) {
    let schema = source;
    for (const part of conflict.pointer.slice(2).split('/')) schema = schema[part.replaceAll('~1', '/').replaceAll('~0', '~')];
    assert.equal(createHash('sha256').update(JSON.stringify(canonical(schema))).digest('hex'), conflict.sourceHash);
    if (conflict.kind === 'description_vs_null_schema') {
      const approved = [...ledger.nullResponses, ...ledger.nullRequests].some(rule => rule.version === version && rule.pointer === conflict.pointer);
      assert.equal(validator.validate(conflict.pointer, null).length === 0, approved, conflict.id);
    }
    for (const assignment of conflict.assignments) for (const caseId of assignment.cases) rows.push({
      version, conflict: conflict.id, pointer: conflict.pointer, operation: assignment.operation, case: caseId, status: conflict.status,
    });
  }
  assert.throws(() => validateResponse(version, 'OP-021', {}), error =>
    error.code === (version === '10.6.109' ? 'RESPONSE_INVALID' : 'CONTRACT_CONFLICT'));
  assert.equal(contractConflicts(version, 'site').length, 0);
  validateResponse(version, 'OP-002', { offset: 0, limit: 0, count: 0, totalCount: 0, data: [] });
  const modified = structuredClone(source);
  modified.components.schemas['Application info'].pattern = 'unsupported';
  assert.throws(() => compileContract(modified, version), /Unsupported validation keyword pattern/);
}
console.log(JSON.stringify({ task: 'B2.1', acceptance: 'STEP-B2.1', status: 'passed',
  publicOperationCasesExecuted: false, rows }, null, 2));
