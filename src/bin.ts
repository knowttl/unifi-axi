#!/usr/bin/env node
import { version } from './version.js';

const args = process.argv.slice(2);
if (args.length === 1 && ['-v', '-V', '--version'].includes(args[0]!)) {
  console.log(version);
} else {
  const { main } = await import('./cli.js');
  process.exitCode = await main(args);
}
