// Capture the Step 8 acceptance outputs as UTF-8 evidence files.
//
// Written from node on purpose: a shell redirection on Windows can re-encode the
// captured bytes (PowerShell 5.1 writes UTF-16 for ">"), which produced mojibake
// evidence earlier in this project.
//
// Usage (from injectionlens/, with the dev servers NOT required for the first
// four commands): node scripts/capture-step8-evidence.js

'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const APP_DIR = path.join(__dirname, '..');
const OUT_DIR = path.join(APP_DIR, 'eval', 'results');

const RUNS = [
  { file: 'stage8-tests.txt', cmd: 'npm', args: ['test'], label: 'npm test' },
  { file: 'stage8-smoke.txt', cmd: 'node', args: ['scripts/smoke.js'], label: 'smoke' },
  { file: 'stage8-fixtures.txt', cmd: 'node', args: ['scripts/run-fixtures.js', '--no-json'], label: 'fixtures' },
  { file: 'stage8-client-build.txt', cmd: 'npm', args: ['--prefix', 'client', 'run', 'build'], label: 'client build' },
];

fs.mkdirSync(OUT_DIR, { recursive: true });

for (const run of RUNS) {
  const result = spawnSync(run.cmd, run.args, {
    cwd: APP_DIR,
    encoding: 'utf8',
    shell: true,
    maxBuffer: 64 * 1024 * 1024,
  });
  const header = `$ ${run.cmd} ${run.args.join(' ')}\n(exit code: ${result.status})\n\n`;
  const body = header + (result.stdout || '') + (result.stderr ? `\n[stderr]\n${result.stderr}` : '');
  fs.writeFileSync(path.join(OUT_DIR, run.file), body, 'utf8');
  console.log(`${run.label.padEnd(14)} exit=${result.status} -> ${run.file} (${Buffer.byteLength(body, 'utf8')} bytes)`);
}
