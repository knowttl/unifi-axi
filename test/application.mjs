import assert from 'node:assert/strict';

// Independent synthetic records, never derived from catalogue or application output.
const first = { id: '9361553d-e20d-45b8-a516-6948ab010011', internalReference: 'north', name: 'North lab' };
const second = { id: '5925a212-9b6e-402b-a675-c658ab010022', internalReference: 'south', name: 'South lab' };

export async function verifyApplication({ cli, configure, trusted, config, seed, requests }) {
  let version = '10.6.109';
  let records = [first, second];
  const serve = request => {
    const url = new URL(request.url, trusted.origin);
    if (url.pathname === '/proxy/network/integration/v1/info') {
      return { applicationVersion: version, siteManagerVersion: '5.2.23' };
    }
    assert.equal(url.pathname, '/proxy/network/integration/v1/sites', 'Only application and site reads are allowed');
    const offset = Number(url.searchParams.get('offset'));
    const limit = Number(url.searchParams.get('limit'));
    const data = records.slice(offset, offset + Math.min(limit, 1));
    return { offset, limit, count: data.length, totalCount: records.length, data };
  };
  const profile = { ...trusted, siteId: first.id };
  configure({ lab: profile });
  for (version of ['10.6.109', '11.0.97']) {
    for (const args of [['info'], ['doctor'], ['site', 'list'], []]) {
      seed(serve);
      const result = await cli(args);
      assert.equal(result.information.applicationVersion, version);
      assert.equal(result.information.siteManagerVersion, '5.2.23');
      assert.deepEqual(result.api, { applicationVersion: version, contract: version, status: 'verified', writesAvailable: false });
      if (args[0] === 'doctor') assert.deepEqual(result.doctor, { credentials: 'resolved', tls: 'verified', application: 'accessible' });
      if (args[0] === 'site' || args.length === 0) {
        assert.deepEqual(result.sites, records);
        assert.equal(result.count, 2);
        assert.equal(result.totalCount, 2);
        assert.equal(result.complete, true);
        assert.equal(result.selectedSite, first.id);
      } else assert.equal(requests().length, 1, 'Info and doctor read only application information');
    }
  }

  seed(serve);
  const selected = await cli(['--profile', 'lab', '--config', config, '--site', second.id], 0,
    { UNIFI_AXI_SITE_ID: first.id });
  assert.equal(selected.selectedSite, second.id, 'Explicit site wins over profile and environment');
  const hints = selected.help.map(hint => hint.match(/(?:[^\s'\\]|'[^']*'|\\.)+/g)
    .map(word => word.replace(/'([^']*)'|\\(.)/g, (_, quoted, escaped) => quoted ?? escaped)));
  for (const hint of hints) {
    assert.deepEqual(hint.slice(3), ['--profile', 'lab', '--config', config, '--site', second.id]);
  }
  const followup = hints.find(hint => hint[1] === 'site' && hint[2] === 'list').slice(1);
  assert.equal((await cli(followup)).selectedSite, second.id, 'Emitted site-list hint is executable');
  const context = followup.slice(2, -2);
  assert.equal((await cli(['auth', 'status', ...context])).auth.profile, 'lab');
  assert.equal((await cli(['config', 'path', ...context])).config.path, config);
  configure({ lab: { ...profile, apiContract: '10.6.109' } });
  assert.deepEqual((await cli(['info'])).api,
    { applicationVersion: '11.0.97', contract: '11.0.97', status: 'verified', writesAvailable: false },
    'Observed known version wins over the profile contract override');
  configure({ lab: trusted });
  seed(serve);
  const ambiguous = await cli([], 1);
  assert.equal(ambiguous.error.code, 'SITE_AMBIGUOUS');
  assert.deepEqual(ambiguous.sites, records);
  assert.equal(requests().some(request => /\/sites\//.test(request.path)), false, 'Ambiguity sends no site-specific request');
  assert.equal((await cli(['site', 'list'])).selectedSite, null, 'Site discovery works before selecting a site');
  records = [first];
  assert.equal((await cli([])).selectedSite, first.id);
  records = [];
  const empty = await cli(['site', 'list']);
  assert.deepEqual(empty.sites, []);
  assert.equal(empty.count, 0);
  assert.equal(empty.totalCount, 0);
  assert.equal(empty.complete, true);
  assert.equal((await cli([], 1)).error.code, 'SITE_REQUIRED');

  records = [first, second];
  seed(serve);
  const page = await cli(['site', 'list', '--offset', '1', '--limit', '1']);
  assert.deepEqual(page.sites, [second]);
  assert.equal(page.count, 1);
  assert.equal(page.totalCount, 2);
  assert.equal(page.complete, true);
  for (const offset of [2, 5]) {
    const beyond = await cli(['site', 'list', '--offset', String(offset)]);
    assert.deepEqual(beyond.sites, []);
    assert.equal(beyond.offset, offset);
    assert.equal(beyond.count, 0);
    assert.equal(beyond.totalCount, 2);
    assert.equal(beyond.complete, true);
  }
  const metadata = await cli(['site', 'list', '--limit', '0']);
  assert.deepEqual(metadata.sites, []);
  assert.equal(metadata.totalCount, 2);
  assert.equal(metadata.complete, false);
  assert.equal(requests().every(request => request.method === 'GET'), true);

  version = '99.0.1';
  for (const args of [['info'], ['doctor'], ['site', 'list'], []]) {
    seed(serve);
    const result = await cli(args, 1);
    assert.equal(result.error.code, 'UNVERIFIED_API_VERSION');
    assert.deepEqual(result.api, { applicationVersion: version, contract: null, status: 'unverified', writesAvailable: false });
    assert.equal(requests().length, 1, 'Unknown versions stop after version bootstrap');
  }
  configure({ lab: { ...profile, apiContract: '11.0.97', writes: { allowWrites: true, operations: ['OP-006'] } } });
  const investigated = await cli([]);
  assert.deepEqual(investigated.api, { applicationVersion: version, contract: '11.0.97', status: 'unverified', writesAvailable: false });
  seed(serve);
  assert.equal((await cli(['device', 'adopt', '--site', first.id], 1)).error.code, 'NOT_IMPLEMENTED');
  assert.deepEqual(requests(), [], 'Writes stay unavailable even with an explicit contract and write settings');

  configure({ lab: profile });
  for (const malformed of [null, {}, { applicationVersion: 11 }, { data: { applicationVersion: '11.0.97' } }]) {
    seed(() => malformed);
    assert.equal((await cli(['info'], 1)).error.code, 'RESPONSE_INVALID');
  }
  version = '11.0.97';
  for (const bad of [
    {}, { offset: 0, limit: 25, count: 1, totalCount: 1, data: [{ ...first, id: 'not-a-uuid' }] },
    { offset: 0, limit: 25, count: 1, totalCount: 1, data: [{ id: first.id, name: first.name }] },
    { offset: 0, limit: 25, count: 0, totalCount: 1, data: [] },
    { offset: 0, limit: 25, count: 1, totalCount: 0, data: [first] },
    { offset: 0, limit: 25, count: '1', totalCount: 1, data: [first] },
  ]) {
    seed(request => request.url.endsWith('/info') ? { applicationVersion: version } : bad);
    const rejected = await cli(['site', 'list'], 1);
    assert.equal(rejected.error.code, 'RESPONSE_INVALID');
    assert.equal(rejected.api.applicationVersion, '11.0.97', 'Site failures retain bootstrap version context');
  }
}
