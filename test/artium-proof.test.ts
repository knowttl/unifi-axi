import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('./fixtures/artium-proof.ts', import.meta.url));
for (const { name, mode, status, stdout, stderr } of [
  { name: 'normal watcher proof completes after scratch cleanup', mode: 'normal', status: 0, stdout: /^proof completed\n$/, stderr: /^$/ },
  { name: 'watcher assertion failure exits nonzero after scratch cleanup (#6)', mode: 'failure', status: 1, stdout: /^$/, stderr: /synthetic callback assertion/ },
]) {
  test(name, () => {
    const temporary = mkdtempSync(join(tmpdir(), 'unifi-artium-proof-'));
    const scratch = join(temporary, 'scratch');
    try {
      const result = spawnSync(process.execPath, [fixture, scratch, mode], { encoding: 'utf8', timeout: 15_000 });
      assert.ifError(result.error);
      assert.equal(result.signal, null);
      assert.equal(result.status, status, result.stderr);
      assert.match(result.stdout, stdout);
      assert.match(result.stderr, stderr);
      assert.equal(existsSync(scratch), false, 'Proof cleanup removes private scratch state');
    } finally {
      rmSync(temporary, { recursive: true, force: true });
    }
  });
}
