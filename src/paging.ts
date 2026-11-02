import { ToolError } from './security.js';
import { readBudget, type ReadBudget } from './transport.js';

export interface Page<T> { offset: number; limit: number; count: number; totalCount: number; data: T[] }

export async function enumerate<T>(read: (offset: number, budget: ReadBudget, limit: number) => Promise<Page<T>>,
  identify: (row: T) => string, offset: number, limit: number,
  bounds = { pages: 100, rows: 10_000, budget: readBudget() }, stopAfterRows?: number) {
  const data: T[] = [];
  const ids = new Set<string>();
  let next = offset;
  let totalCount: number | undefined;
  const incomplete = (reason: string): never => {
    throw new ToolError('READ_INCOMPLETE', `Read incomplete: ${reason}; returned ${data.length} rows, next offset ${next}. Narrow the filter.`);
  };
  for (let pages = 0; pages < bounds.pages; pages++) {
    if (Date.now() >= bounds.budget.deadline) incomplete('time budget exceeded');
    const requestedLimit = stopAfterRows === undefined ? limit : Math.min(limit, stopAfterRows - data.length);
    let page: Page<T>;
    try { page = await read(next, bounds.budget, requestedLimit); }
    catch (error) {
      if (error instanceof ToolError && ['TIMEOUT', 'READ_INCOMPLETE'].includes(error.code)) incomplete(error.message);
      throw error;
    }
    if (page.offset !== next) incomplete('offset did not advance as requested');
    if (totalCount !== undefined && page.totalCount !== totalCount) incomplete('totalCount changed');
    if (page.count > requestedLimit || (page.count > 0 && next + page.count > page.totalCount)) incomplete('count exceeds requested or reported bounds');
    totalCount = page.totalCount;
    if (data.length + page.count > bounds.rows) incomplete('row budget exceeded');
    for (const row of page.data) {
      const id = identify(row);
      if (ids.has(id)) incomplete('repeated records');
      ids.add(id);
      data.push(row);
    }
    next += page.count;
    if (next >= totalCount || limit === 0) return { data, offset, count: data.length, totalCount, complete: next >= totalCount,
      ...(next < totalCount ? { nextOffset: next } : {}) };
    if (stopAfterRows !== undefined && data.length >= stopAfterRows) return { data, offset, count: data.length, totalCount, complete: false, nextOffset: next };
    if (page.count === 0) incomplete('offset stalled');
  }
  return incomplete('page budget exceeded');
}
