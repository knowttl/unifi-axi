import assert from 'node:assert/strict';
import test from 'node:test';
import { enumerate } from '../dist/paging.js';

const page = (offset, data, totalCount = 3) => ({ offset, limit: 2, count: data.length, totalCount, data });
const bounds = overrides => ({ pages: 5, rows: 5, budget: { deadline: Date.now() + 1000, bytes: 1000 }, ...overrides });
test('enumerates exact rows and metadata across pages', async () => {
  assert.deepEqual(await enumerate(async offset => page(offset, offset === 0 ? ['a', 'b'] : ['c']), row => row, 0, 2),
    { data: ['a', 'b', 'c'], offset: 0, count: 3, totalCount: 3, complete: true });
});
for (const [reason, read, limits] of [
  ['repeated records', async offset => page(offset, ['a']), {}],
  ['offset did not advance', async () => page(1, ['a']), {}],
  ['totalCount changed', async offset => page(offset, ['a'], offset ? 4 : 3), {}],
  ['offset stalled', async offset => page(offset, []), {}],
  ['row budget', async offset => page(offset, ['a', 'b']), { rows: 1 }],
  ['page budget', async offset => page(offset, ['a']), { pages: 1 }],
  ['time budget', async offset => page(offset, ['a']), { budget: { deadline: 0, bytes: 1000 } }],
]) test(`reports incomplete enumeration: ${reason}`, async () => {
  await assert.rejects(enumerate(read, row => row, 0, 2, bounds(limits)), error => error.code === 'READ_INCOMPLETE' && error.message.includes(reason));
});
