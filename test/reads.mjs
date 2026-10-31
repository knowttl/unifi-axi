import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const records = Array.from({ length: 3 }, (_, index) => ({
  id: `9361553d-e20d-45b8-a516-6948ab01001${index}`, internalReference: `lab-${index}`, name: `Lab ${index}`,
}));
const seeded = [...records, { id: '9361553d-e20d-45b8-a516-6948ab010019', internalReference: 'excluded', name: 'excluded' }];

export async function verifyReads({ cli, configure, trusted, seed, requests, installed }) {
  configure({ lab: trusted });
  const info = { applicationVersion: '11.0.97' };
  const serve = request => {
    const url = new URL(request.url, trusted.origin);
    if (url.pathname.endsWith('/info')) return info;
    assert.equal(url.searchParams.get('filter'), "name.ne('excluded')");
    const offset = Number(url.searchParams.get('offset'));
    const filtered = seeded.filter(record => record.name !== 'excluded');
    const data = filtered.slice(offset, offset + 1);
    return { offset, limit: 1, count: data.length, totalCount: filtered.length, data };
  };
  seed(serve);
  const result = await cli(['site', 'list', '--limit', '1', '--filter', "name.ne('excluded')"]);
  assert.deepEqual(result.sites, records);
  assert.deepEqual([result.count, result.totalCount, result.complete], [3, 3, true]);
  assert.equal(requests().length, 4, 'Bootstrap plus three filtered pages');
  seed(request => request.url.endsWith('/info') ? info : { offset: 0, limit: 0, count: 0, totalCount: 3, data: [] });
  assert.equal((await cli(['site', 'list', '--limit', '0'])).complete, false);
  assert.equal(requests().length, 2, 'Limit zero sends one metadata request after bootstrap');

  for (const [status, after, expectedRequests] of [[401, null, 1], [429, '1', 2], [429, '999999', 1], [429, '-1', 1], [503, null, 2]]) {
    let calls = 0;
    seed((request, response) => {
      if (++calls > 1) return info;
      response.statusCode = status;
      if (after !== null) response.setHeader('Retry-After', after);
      response.end();
    });
    const started = performance.now();
    const result = await cli(['info'], expectedRequests === 1 ? 1 : 0);
    if (after === '1') assert.ok(performance.now() - started >= 1000, 'Honours safe Retry-After delta');
    assert.equal(requests().length, expectedRequests);
    if (expectedRequests === 1) assert.equal(result.error.code, 'UPSTREAM_ERROR');
    else assert.equal(result.information.applicationVersion, '11.0.97');
  }
  seed((request, response) => {
    response.writeHead(302, { Location: `${trusted.origin}/redirect-target` });
    response.end();
  });
  assert.equal((await cli(['info'], 1)).error.code, 'UPSTREAM_ERROR');
  assert.equal(requests().length, 1, 'Redirect destination receives no authenticated request');

  for (const [body, code] of [['{malformed', 'RESPONSE_INVALID'], [' '.repeat(1024 * 1024 + 1), 'READ_INCOMPLETE']]) {
    seed((request, response) => { response.end(body); });
    assert.equal((await cli(['info'], 1)).error.code, code);
    assert.equal(requests().length, 1);
  }
  seed(request => request.url.endsWith('/info') ? info : { offset: 0, limit: 1, count: 1, totalCount: 3, data: [records[0]] });
  assert.equal((await cli(['site', 'list', '--limit', '1'], 1)).error.code, 'READ_INCOMPLETE');

  const { readJson } = await import(pathToFileURL(join(installed, 'dist/transport.js')));
  const intervals = [];
  seed((request, response) => {
    const interval = { start: performance.now(), end: Infinity };
    intervals.push(interval);
    // Synthetic server latency keeps competing reads in flight together.
    setTimeout(() => { interval.end = performance.now(); response.end(JSON.stringify(info)); }, 30);
  });
  await Promise.all(Array.from({ length: 6 }, () => readJson(trusted, 'synthetic-concurrency-key', '/v1/info')));
  assert.equal(intervals.length, 6);
  const events = intervals.flatMap(interval => [[interval.start, 1], [interval.end, -1]]).sort((a, b) => a[0] - b[0]);
  let active = 0, peak = 0;
  for (const [, change] of events) { active += change; peak = Math.max(peak, active); }
  assert.equal(peak, 2, 'At most two authenticated reads arrive concurrently');

  seed(() => info);
  await assert.rejects(readJson(trusted, 'synthetic-budget-key', '/v1/info', { deadline: Date.now() + 1000, bytes: 1 }),
    error => error.code === 'READ_INCOMPLETE', 'Aggregate response byte budget is enforced');

  seed((request, response) => { response.writeHead(429, { 'Retry-After': '2' }); response.end(); });
  await assert.rejects(readJson(trusted, 'synthetic-budget-key', '/v1/info', { deadline: Date.now() + 1000, bytes: 1000 }),
    error => error.code === 'TIMEOUT', 'Retry delay cannot exceed the overall deadline');
  assert.equal(requests().length, 1);

  seed((request, response) => { response.write('{'); });
  const started = performance.now();
  assert.equal((await cli(['info'], 1)).error.code, 'TIMEOUT');
  assert.ok(performance.now() - started >= 9900, 'Tool deadline, with host deadline safely longer');
}
