import { versions } from './catalogue.js';
import type { Profile } from './profiles.js';
import { ToolError } from './security.js';
import { readJson } from './transport.js';

interface Site { id: string; internalReference: string; name: string }
interface SitePage { offset: number; limit: number; count: number; totalCount: number; data: Site[] }

function invalid(): never { throw new ToolError('RESPONSE_INVALID', 'Application or site response does not match the selected contract.'); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  return value as Record<string, unknown>;
}

export async function application(profile: Profile, secret: string) {
  const information = object(await readJson(profile, secret, '/v1/info'));
  if (typeof information.applicationVersion !== 'string') invalid();
  const actual = information.applicationVersion;
  const verified = versions.some(version => version === actual);
  return { information, api: { applicationVersion: actual,
    contract: verified ? actual : profile.apiContract ?? null,
    status: verified ? 'verified' : 'unverified', writesAvailable: false } };
}

// Only the identical info/site schemas in the two shipped contracts are implemented here.
function sitePage(value: unknown): SitePage {
  const page = object(value);
  for (const field of ['offset', 'limit', 'count', 'totalCount']) {
    if (!Number.isSafeInteger(page[field]) || (page[field] as number) < 0 ||
      (['limit', 'count'].includes(field) && (page[field] as number) > 2147483647)) invalid();
  }
  if (!Array.isArray(page.data)) invalid();
  for (const value of page.data) {
    const site = object(value);
    if (typeof site.id !== 'string' || !/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(site.id) ||
      typeof site.internalReference !== 'string' || typeof site.name !== 'string') invalid();
  }
  if (page.count !== page.data.length) invalid();
  return page as unknown as SitePage;
}

export async function sites(profile: Profile, secret: string, values: Record<string, string>) {
  const offset = Number(values.offset ?? 0);
  const limit = Number(values.limit ?? 25);
  const data: Site[] = [];
  let next = offset;
  let totalCount: number | undefined;
  const ids = new Set<string>();
  for (let pages = 0; pages < 100; pages++) {
    const query = new URLSearchParams({ offset: String(next), limit: String(limit) });
    if (values.filter !== undefined) query.set('filter', values.filter);
    const page = sitePage(await readJson(profile, secret, `/v1/sites?${query}`));
    if (page.offset !== next || (totalCount !== undefined && page.totalCount !== totalCount) ||
      page.count > limit || page.offset + page.count > page.totalCount) invalid();
    totalCount = page.totalCount;
    for (const site of page.data) {
      if (ids.has(site.id)) invalid();
      ids.add(site.id);
      data.push(site);
    }
    next += page.count;
    if (next >= totalCount || limit === 0) return { sites: data, offset, count: data.length, totalCount,
      complete: next >= totalCount };
    if (page.count === 0) invalid();
  }
  throw new ToolError('READ_INCOMPLETE', 'Site enumeration reached its 100-page bound. Narrow the filter.');
}

export function selectSite(data: Site[], explicit?: string): string {
  if (explicit !== undefined) {
    return explicit;
  }
  if (data.length === 0) throw new ToolError('SITE_REQUIRED', 'No local sites are available.');
  if (data.length > 1) throw new ToolError('SITE_AMBIGUOUS', 'Multiple sites are available. Select one with --site <site-id>.');
  return data[0]!.id;
}
