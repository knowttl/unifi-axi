import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, watch, writeFileSync, type FSWatcher } from 'node:fs';
import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { runArtiumProof } from '../../scripts/artium-proof.ts';

const scratch = process.argv[2]!;
const mode = process.argv[3]!;
const trigger = join(scratch, 'trigger');
const observed = Promise.withResolvers<void>();
let watcher: FSWatcher | undefined;
mkdirSync(scratch, { mode: 0o700 });
writeFileSync(join(scratch, 'server.key'), 'synthetic private state', { mode: 0o600 });

await runArtiumProof(async guard => {
  watcher = watch(scratch, guard(() => {
    assert.equal(readFileSync(trigger, 'utf8'), 'expected', 'synthetic callback assertion (#6)');
    observed.resolve();
  }));
  writeFileSync(trigger, mode === 'normal' ? 'expected' : 'unexpected');
  await observed.promise;
}, async () => {
  watcher?.close();
  await rm(scratch, { recursive: true, force: true });
});
assert.equal(existsSync(scratch), false, 'Cleanup finishes before the proof settles');
process.stdout.write('proof completed\n');
