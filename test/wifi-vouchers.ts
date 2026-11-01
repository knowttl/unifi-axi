import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Harness } from './writes.ts';

const site = '9361553d-e20d-45b8-a516-6948ab010011';
const ids = [1, 2, 3, 4, 5].map(n => `8c850c83-1111-4111-8111-${String(n).padStart(12, '0')}`);
const id = ids[0]!;
const neighbourId = ids[4]!;
export const wifi = { name: 'Synthetic Wi-Fi', type: 'STANDARD', enabled: true, broadcastingFrequenciesGHz: [2.4, 5],
  channel2gLockedTo6: false, clientIsolationEnabled: true, dtimPeriod2gLockedTo3: false, hideName: false,
  multicastToUnicastConversionEnabled: true, uapsdEnabled: true, advertiseDeviceName: false, arpProxyEnabled: true,
  bssTransitionEnabled: true, securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'SYNTHETIC-WIFI-48291' } };
const voucher = { name: 'Synthetic voucher', timeLimitMinutes: 60, authorizedGuestLimit: 2, dataUsageLimitMBytes: 256,
  rxRateLimitKbps: 1000, txRateLimitKbps: 500 };
const metadata = { origin: 'USER_DEFINED' };
type Row = Record<string, unknown>;

const services = ['AMAZON_DEVICES', 'ANDROID_TV_REMOTE', 'APPLE_AIR_DROP', 'APPLE_AIR_PLAY', 'APPLE_FILE_SHARING',
  'APPLE_ICHAT', 'APPLE_ITUNES', 'AQARA', 'BOSE', 'DNS_SERVICE_DISCOVERY', 'FTP_SERVERS', 'GOOGLE_CHROMECAST',
  'HOMEKIT', 'MATTER_NETWORK', 'PHILIPS_HUE', 'PRINTERS', 'ROKU', 'SCANNERS', 'SHELLY', 'SONOS', 'SPOTIFY_CONNECT',
  'SSH_SERVERS', 'TIME_CAPSULE', 'WEB_SERVERS', 'WINDOWS_FILE_SHARING_SAMBA'];
const macFormats = ['UPPERCASE_NOT_SEPARATED', 'UPPERCASE_DASH_SEPARATED', 'UPPERCASE_COLON_SEPARATED',
  'LOWERCASE_NOT_SEPARATED', 'LOWERCASE_COLON_SEPARATED', 'LOWERCASE_DASH_SEPARATED'];
const securityTypes = ['OPEN', 'WPA2_PERSONAL', 'WPA2_ENTERPRISE', 'WPA2_WPA3_PERSONAL', 'WPA2_WPA3_ENTERPRISE', 'WPA3_PERSONAL', 'WPA3_ENTERPRISE'];
const networks = [{ type: 'NATIVE' }, { type: 'SPECIFIC', networkId: neighbourId }];
const deviceFilters = [{ type: 'DEVICES', deviceIds: [id] }, { type: 'DEVICE_TAGS', deviceTagIds: [neighbourId] }];
const wifiVariants = ['STANDARD', 'IOT_OPTIMIZED'].flatMap(type => securityTypes.flatMap(securityType =>
  [...macFormats, macFormats[0]!, macFormats[1]!].map((macAddressFormat, index) => {
    const nasId = index < 4 ? { type: 'DERIVED', source: ['DEVICE_MAC_ADDRESS', 'DEVICE_NAME', 'SITE_NAME', 'BSSID'][index] } :
      { type: 'USER_DEFINED', value: 'synthetic-nas' };
    const radiusConfiguration = { profileId: neighbourId, nasId, macAuthenticationConfiguration: { macAddressFormat } };
    const securityConfiguration: Row = { type: securityType, radiusConfiguration };
    if (securityType === 'OPEN') securityConfiguration.encryption = index % 2 ? 'ENHANCED_OPEN' : 'ENHANCED_OPEN_WITH_TRANSITION';
    if (securityType.includes('PERSONAL')) securityConfiguration.passphrase = wifi.securityConfiguration.passphrase;
    if (securityType.includes('ENTERPRISE')) securityConfiguration.coaEnabled = true;
    if (securityType === 'WPA2_PERSONAL') securityConfiguration.presharedKeys = networks.map(network => ({ network, passphrase: 'SYNTHETIC-PPSK-48291' }));
    if (securityType.includes('WPA2') && type === 'STANDARD') securityConfiguration.pmfMode = index % 2 ? 'REQUIRED' : 'OPTIONAL';
    if (securityType.includes('WPA2_WPA3')) {
      securityConfiguration.pmfMode = index % 2 ? 'REQUIRED' : 'OPTIONAL';
      securityConfiguration.wpa3FastRoamingEnabled = false;
    }
    if (securityType === 'WPA3_ENTERPRISE') securityConfiguration.securityMode = index % 2 ? 'DEFAULT' : 'HIGH_SECURITY_192_BIT';
    if (['WPA3_PERSONAL', 'WPA2_WPA3_PERSONAL'].includes(securityType)) securityConfiguration.saeConfiguration = { anticloggingThresholdSeconds: 5, syncTimeSeconds: 7 };
    const common = { ...wifi, type, securityConfiguration, network: networks[index % 2], broadcastingDeviceFilter: deviceFilters[index % 2],
      basicDataRateKbpsByFrequencyGHz: { '2.4': [1000, 2000, 5500, 6000, 9000, 11000, 12000, 24000][index], '5': [6000, 9000, 12000, 24000][index % 4] },
      clientFilteringPolicy: { action: index % 2 ? 'ALLOW' : 'BLOCK', macAddressFilter: ['02:00:00:00:00:01'] },
      multicastFilteringPolicy: index % 2 ? { action: 'ALLOW', sourceMacAddressFilter: ['02:00:00:00:00:02'] } : { action: 'BLOCK' },
      mdnsProxyConfiguration: index % 2 ? { mode: 'AUTO' } : { mode: 'CUSTOM', policies: deviceFilters.flatMap(deviceFilter => [
        { action: 'ALLOW', deviceFilter, bridgingNetworkIds: [neighbourId], serviceFilter: [
          { type: 'CUSTOM', name: 'synthetic', typeDomain: '_synthetic._tcp.local' },
          ...services.map(name => ({ type: 'PREDEFINED', name })),
        ] }, { action: 'BLOCK', deviceFilter },
      ]) },
      blackoutScheduleConfiguration: { days: ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'].flatMap(day => [
        { type: 'ALL_DAY', day }, { type: 'TIME_RANGE', day, timeRanges: [{ startTime: '01:00', endTime: '02:00' }] },
      ]) } };
    if (type === 'IOT_OPTIMIZED') return Object.fromEntries(Object.entries(common).filter(([key]) =>
      !['advertiseDeviceName', 'arpProxyEnabled', 'bssTransitionEnabled', 'broadcastingFrequenciesGHz'].includes(key)));
    return { ...common, broadcastingFrequenciesGHz: [2.4, 5, 6], dnsAssistanceConfiguration: index % 2 ? { mode: 'AUTO' } : { mode: 'MANUAL', servers: ['192.0.2.53'] },
      hotspotConfiguration: { type: index % 2 ? 'CAPTIVE_PORTAL' : 'PASSPOINT' },
      dtimPeriodByFrequencyGHzOverride: { '2.4': 3, '5': 2, '6': 1 }, handoffSuggestionsConfiguration: { band5GHzRssiThreshold: -70, band6GHzRssiThreshold: -80 } };
  })));

export async function verifyWifiVouchers(h: Harness) {
  const rows: Row[] = [];
  const guard = fileURLToPath(new URL('./fixtures/write-guard.ts', import.meta.url));
  const env = { NODE_OPTIONS: `--import=${guard}`, UNIFI_AXI_TEST_PORT: String(h.port), UNIFI_AXI_WRITE_LOG: join(h.home, 'wifi-voucher-journal') };
  const run = (args: string[], code = 0, overrides: Record<string, string> = {}) => h.cli(args, code, { ...env, ...overrides });
  const profile = { ...h.trusted, siteId: site, allowSecretExport: true, writes: { allowWrites: true,
    operations: ['createWifiBroadcast', 'updateWifiBroadcast', 'deleteWifiBroadcast', 'createVouchers', 'deleteVouchers', 'deleteVoucher'] } };
  const bodyFile = join(h.home, 'wifi-voucher-body.json');
  const execute = (args: string[], confirmation: string, requestId: string) => [...args, '--execute', '--confirm', confirmation, '--request-id', requestId];
  h.configure({ lab: profile });
  for (const version of ['10.6.109', '11.0.97']) {
    for (const family of ['wifi', 'voucher'] as const) {
      if (family === 'voucher' && h.task === 'B4.7') continue;
      if (process.platform === 'win32') { rows.push({ task: h.task, status: 'pending-native-windows' }); continue; }
      const prefix = family === 'wifi' ? ['wifi', 'broadcast'] : ['hotspot', 'voucher'];
      const targetFlag = family === 'wifi' ? '--wifi-broadcast-id' : '--voucher-id';
      const collection = `/proxy/network/integration/v1/sites/${site}/${family === 'wifi' ? 'wifi/broadcasts' : 'hotspot/vouchers'}`;
      const body = family === 'wifi' ? wifi : voucher;
      const decorate = (body: Row, id: string): Row => family === 'wifi' ? { ...body, id, metadata } :
        { ...body, id, code: `SYNTHETIC-CODE-${id}`, authorizedGuestCount: 0, createdAt: '2026-10-30T12:00:00Z', expired: false };
      const neighbour = decorate({ ...body, name: 'Untouched neighbour' }, neighbourId);
      let state = [neighbour];
      const mutations: { method: string; path: string; body: unknown }[] = [];
      let injectLate = false;
      let badAck = false;
      h.seed((request, response) => {
        assert.equal(request.headers['x-api-key'], h.syntheticKey);
        const url = new URL(request.url!, h.trusted.origin);
        if (url.pathname.endsWith('/info')) return { applicationVersion: version };
        assert.ok(url.pathname === collection || url.pathname.startsWith(`${collection}/`), 'Selected site and family only');
        if (request.method === 'GET') {
          if (url.pathname !== collection) return state.find(row => row.id === url.pathname.split('/').at(-1));
          const filtered = url.searchParams.has('filter') ? state.filter(row => row.name === body.name) : state;
          return { offset: 0, limit: 25, count: filtered.length, totalCount: filtered.length, data: filtered };
        }
        let bytes = '';
        request.on('data', chunk => { bytes += chunk; });
        request.on('end', () => {
          const parsed = bytes ? JSON.parse(bytes) as Row : null;
          mutations.push({ method: request.method!, path: request.url!, body: parsed });
          if (badAck) { response.statusCode = 403; response.end('{}'); return; }
          let result: unknown;
          if (request.method === 'POST') {
            const count = Number(parsed!.count ?? 1);
            const created = ids.slice(0, count).map(id => decorate(Object.fromEntries(Object.entries(parsed!).filter(([key]) => key !== 'count')), id));
            state.push(...created);
            result = family === 'wifi' ? created[0] : { vouchers: created };
          } else if (request.method === 'PUT') {
            const row = decorate(parsed!, id);
            state = state.map(old => old.id === id ? row : old);
            result = row;
          } else if (url.pathname === collection) {
            if (injectLate) state.push(decorate(body, ids[3]!));
            // Parse the serialized conjunction independently, then evaluate the ID set.
            const match = /^and\(name\.eq\('([^']+)'\),id\.in\(([^)]+)\)\)$/.exec(url.searchParams.get('filter')!);
            assert.ok(match, 'Bulk request retains the original predicate AND a UUID set');
            assert.equal(match[1], body.name);
            const approved = match[2]!.split(',');
            assert.deepEqual(approved, ids.slice(0, 3));
            state = state.filter(row => row.name !== match[1] || !approved.includes(String(row.id)));
            result = { vouchersDeleted: approved.length };
          } else {
            state = state.filter(row => row.id !== id);
            result = family === 'wifi' ? undefined : { vouchersDeleted: 1 };
          }
          response.statusCode = request.method === 'POST' ? 201 : 200;
          response.end(result === undefined ? '' : JSON.stringify(result));
        });
      });
      for (const count of family === 'wifi' ? [1] : [undefined, 3]) {
        state = [neighbour];
        const requested = { ...body, ...(count === 3 ? { count } : {}) };
        writeFileSync(bodyFile, JSON.stringify(requested), { mode: 0o600 });
        const destination = join(h.home, `${family}-${version}-${count}-secrets.json`);
        const args = [...prefix, 'create', '--body-file', bodyFile, '--secret-output', destination];
        h.configure({ lab: { ...profile, allowSecretExport: false } });
        const beforeDenied = h.requests().length;
        assert.equal((await run(args, 1)).error.code, 'SECRET_EXPORT_DENIED');
        assert.equal(h.requests().length, beforeDenied);
        h.configure({ lab: profile });
        const confirmation = (await run(args)).preview.confirmation;
        if (family === 'voucher' && count === undefined) {
          writeFileSync(bodyFile, JSON.stringify({ ...requested, count: 1 }));
          assert.equal((await run(args)).preview.confirmation, confirmation, 'Omitted count and its effective default bind equally');
          writeFileSync(bodyFile, JSON.stringify(requested));
        }
        const before = mutations.length;
        writeFileSync(destination, 'occupied', { mode: 0o600 });
        assert.equal((await run(execute(args, confirmation, `reserve-${family}-${version}-${count}`), 1)).error.code, 'OUTPUT_EXISTS');
        assert.equal(mutations.length, before, 'Reservation failure sends zero mutations');
        const failedDestination = join(h.home, `${family}-${version}-${count}-failed.json`);
        const failedArgs = [...prefix, 'create', '--body-file', bodyFile, '--secret-output', failedDestination];
        const failedConfirmation = (await run(failedArgs)).preview.confirmation;
        const requestId = `create-${family}-${version}-${count}`;
        const failure = await run(execute(failedArgs, failedConfirmation, requestId), 0,
          { UNIFI_AXI_TEST_FAULT: 'secret-disk', UNIFI_AXI_TEST_SECRET_DESTINATION: failedDestination });
        assert.equal(failure.write.outcome, 'verified');
        assert.equal(JSON.stringify(failure).includes(family === 'wifi' ? wifi.securityConfiguration.passphrase : 'SYNTHETIC-CODE-'), false);
        assert.deepEqual(failure.delivery, { path: failedDestination, delivered: false });
        assert.equal(existsSync(failedDestination), false);
        const expectedIds = ids.slice(0, count ?? 1);
        assert.deepEqual(family === 'wifi' ? [failure.write.target] : failure.write.targets, expectedIds);
        assert.deepEqual(state, [neighbour, ...expectedIds.map(id => decorate(body, id))]);
        const recovered = await run(execute(failedArgs, failedConfirmation, requestId));
        assert.equal(recovered.write.outcome, 'verified');
        assert.equal(recovered.delivery!.delivered, true);
        assert.deepEqual(JSON.parse(readFileSync(failedDestination, 'utf8')), { operation: family === 'wifi' ? 'OP-070' : 'OP-045',
          secrets: expectedIds.map(id => ({ id, path: family === 'wifi' ? '/securityConfiguration/passphrase' : '/code',
            value: family === 'wifi' ? wifi.securityConfiguration.passphrase : `SYNTHETIC-CODE-${id}` })) });
        assert.equal(mutations.length, before + 1, 'Recovery reads all stored IDs without generating again');
        rows.push({ task: family === 'wifi' ? 'B4.7' : 'B4.8', operation: family === 'wifi' ? 'OP-070' : 'OP-045', version,
          status: 'passed', direction: 'reservation-delivery-failure-and-exact-batch-recovery', count: count ?? 1 });
      }
      if (family === 'wifi') {
        for (const [index, requested] of (h.task === 'B4.8' ? [] : wifiVariants).entries()) {
          state = [neighbour];
          writeFileSync(bodyFile, JSON.stringify(requested));
          for (const [verb, operation] of [['create', 'OP-070'], ['update', 'OP-073']] as const) {
            const args = [...prefix, verb, '--body-file', bodyFile, ...(verb === 'update' ? [targetFlag, id] : [])];
            const confirmation = (await run(args)).preview.confirmation;
            const before = mutations.length;
            assert.equal((await run(execute(args, confirmation, `variant-${verb}-${version}-${index}`))).write.outcome, 'verified');
            assert.deepEqual(mutations.slice(before), [{ method: verb === 'create' ? 'POST' : 'PUT', path: collection + (verb === 'update' ? `/${id}` : ''), body: requested }]);
            assert.deepEqual(state, [neighbour, decorate(requested, id)]);
            rows.push({ task: 'B4.7', operation, version, variant: index, status: 'passed', direction: 'exact-settings-and-nested-enums' });
          }
        }
        const requested = { ...wifi, name: 'Replacement Wi-Fi', enabled: false };
        writeFileSync(bodyFile, JSON.stringify(requested));
        const args = [...prefix, 'update', targetFlag, id, '--body-file', bodyFile];
        const confirmation = (await run(args)).preview.confirmation;
        const before = mutations.length;
        writeFileSync(bodyFile, JSON.stringify({ ...requested, enabled: true }));
        assert.equal((await run(execute(args, confirmation, `drift-${version}`), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(mutations.length, before);
        writeFileSync(bodyFile, JSON.stringify(requested));
        assert.equal((await run(execute(args, confirmation, `update-${version}`))).write.outcome, 'verified');
        assert.deepEqual(state, [neighbour, decorate(requested, id)]);
        writeFileSync(bodyFile, JSON.stringify({ ...wifi, basicDataRateKbpsByFrequencyGHz: { '2.4': '2000', '5': 6000 } }));
        assert.equal((await run([...prefix, 'create', '--body-file', bodyFile], 1)).error.code, 'INVALID_ARGUMENT');
        rows.push({ task: 'B4.7', operation: 'OP-073', version, status: 'passed', direction: 'replacement-and-stale-preview' });
      } else {
        const args = [...prefix, 'delete-many', '--filter', `name.eq('${body.name}')`];
        const confirmation = (await run(args)).preview.confirmation;
        const before = mutations.length;
        assert.equal((await run(execute([...prefix, 'delete-many', '--filter', "name.eq('different')"], confirmation, `filter-drift-${version}`), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal((await run([...prefix, 'delete-many', '--filter', "name.eq('x')) or (expired.eq(true)"], 1)).error.code, 'INVALID_ARGUMENT');
        state.push(decorate(body, ids[3]!));
        assert.equal((await run(execute(args, confirmation, `bulk-drift-${version}`), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(mutations.length, before);
        state.pop();
        injectLate = true;
        assert.equal((await run(execute(args, confirmation, `bulk-${version}`))).write.outcome, 'verified');
        assert.deepEqual(state, [neighbour, decorate(body, ids[3]!)]);
        state = [neighbour];
        const empty = (await run(args)).preview.confirmation;
        assert.equal((await run(execute(args, empty, `bulk-empty-${version}`))).write.outcome, 'no-op');
        assert.equal(mutations.length, before + 1);
        state.push(decorate(body, id));
        rows.push({ task: 'B4.8', operation: 'OP-043', version, status: 'passed', direction: 'conjoined-filter-late-arrival-drift-empty' });
      }
      const args = [...prefix, 'delete', targetFlag, id];
      const confirmation = (await run(args)).preview.confirmation;
      badAck = true;
      assert.equal((await run(execute(args, confirmation, `delete-denied-${family}-${version}`), 1)).write.outcome, 'unknown');
      badAck = false;
      assert.equal((await run(execute(args, confirmation, `delete-${family}-${version}`))).write.outcome, 'verified');
      assert.deepEqual(state, [neighbour]);
      rows.push({ task: family === 'wifi' ? 'B4.7' : 'B4.8', operation: family === 'wifi' ? 'OP-071' : 'OP-046', version,
        status: 'passed', direction: 'exact-delete-and-http-failure' });
    }
  }
  return rows;
}
