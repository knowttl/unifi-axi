import { createHash } from 'node:crypto';
import { ToolError } from './security.js';

// Every local integration effect binds confirmation to both desired and observed state.
export function effectPolicy(binding: unknown, execute: boolean, confirmation?: string): string {
  const digest = createHash('sha256').update(JSON.stringify(binding)).digest('hex');
  if (execute && confirmation !== digest) {
    throw new ToolError('CONFIRMATION_REQUIRED', 'Preview this exact setup and repeat with --execute --confirm <digest>.');
  }
  return digest;
}
