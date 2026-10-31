import { versions } from './catalogue.js';
import { writeAllowed, type Profile } from './profiles.js';
import { ToolError } from './security.js';
import { readJson, readBudget, type PeerIdentity } from './transport.js';
import { enumerate } from './paging.js';
import { validateResponse } from './validation.js';

interface Site { id: string; internalReference: string; name: string }
interface SitePage { offset: number; limit: number; count: number; totalCount: number; data: Site[] }

function invalid(): never { throw new ToolError('RESPONSE_INVALID', 'Application or site response does not match the selected contract.'); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

export async function application(profile: Profile, secret: string, peer?: PeerIdentity) {
  const information = object(await readJson(profile, secret, '/v1/info', readBudget(), peer));
  if (typeof information.applicationVersion !== 'string') invalid();
  const actual = information.applicationVersion;
  const verified = versions.some(version => version === actual);
  if (verified) validateResponse(actual, 'OP-001', information);
  return { information, api: { applicationVersion: actual,
    contract: verified ? actual : profile.apiContract ?? null,
    status: verified ? 'verified' : 'unverified', writesAvailable: verified && process.platform !== 'win32' &&
      (writeAllowed(profile, ['deleteNetwork']) || writeAllowed(profile, ['createNetwork', 'createNetwork:UNMANAGED'])) } };
}

// Schema validation precedes pagination checks on safe local counters.
function sitePage(page: SitePage): SitePage {
  for (const field of ['offset', 'limit', 'count', 'totalCount']) {
    const value = page[field as 'offset' | 'limit' | 'count' | 'totalCount'];
    if (!Number.isSafeInteger(value) || value < 0) invalid();
  }
  if (page.count !== page.data.length) invalid();
  return page;
}

export async function sites(profile: Profile, secret: string, values: Record<string, string>, version: string, boundedOrPeer: boolean | PeerIdentity = false) {
  const bounded = boundedOrPeer === true;
  const peer = typeof boundedOrPeer === 'object' ? boundedOrPeer : undefined;
  const offset = Number(values.offset ?? 0);
  const limit = Number(values.limit ?? 25);
  const read = async (next: number, budget?: Parameters<typeof readJson>[3]) => {
    const query = new URLSearchParams({ offset: String(next), limit: String(bounded ? Math.min(limit, 25 - next) : limit) });
    if (values.filter !== undefined) query.set('filter', values.filter);
    const value = await readJson(profile, secret, `/v1/sites?${query}`, budget, peer);
    validateResponse(version, 'OP-002', value);
    return sitePage(value as SitePage);
  };
  const result = await enumerate(read, site => site.id, offset, limit, undefined, bounded ? 25 : undefined);
  const { data, ...metadata } = result;
  return { sites: data, ...metadata,
    ...(bounded ? { truncation: { truncated: !metadata.complete, originalCount: metadata.totalCount,
      fullCommand: 'unifi-axi site list' } } : {}) };
}

export function selectSite(data: Site[], explicit?: string): string {
  if (explicit !== undefined) {
    return explicit;
  }
  if (data.length === 0) throw new ToolError('SITE_REQUIRED', 'No local sites are available.');
  if (data.length > 1) throw new ToolError('SITE_AMBIGUOUS', 'Multiple sites are available. Select one with --site <site-id>.');
  return data[0]!.id;
}
