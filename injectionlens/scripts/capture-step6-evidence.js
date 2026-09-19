// Capture the Step 6 validation outputs as UTF-8 evidence files.
//
// Written from node on purpose: a shell redirection on Windows can re-encode the
// captured bytes (PowerShell 5.1 writes UTF-16 for ">"), which produced mojibake
// evidence earlier in this project.
//
// Usage: node scripts/capture-step6-evidence.js
//
// Evidence: Step 6 contract section 4 (validation order and required outputs).

'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const HERE = __dirname;
const APP_DIR = path.join(HERE, '..');
const OUT_DIR = path.join(APP_DIR, 'eval', 'results');

const RUNS = [
  { file: 'stage6-tests.txt', cmd: 'npm', args: ['test'], label: 'npm test' },
  { file: 'stage6-manifest-tests.txt', cmd: 'node', args: ['--test', 'test/fixture-manifest.test.js'], label: 'manifest tests' },
  { file: 'stage6-runner-tests.txt', cmd: 'node', args: ['--test', 'test/fixture-runner.test.js'], label: 'runner tests' },
  { file: 'stage6-fixtures-cli.txt', cmd: 'node', args: ['scripts/run-fixtures.js', '--json', 'eval/results/stage6-fixtures.json'], label: 'fixture runner' },
  { file: 'stage6-smoke.txt', cmd: 'node', args: ['scripts/smoke.js'], label: 'smoke' },
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
  const target = path.join(OUT_DIR, run.file);
  fs.writeFileSync(target, body, 'utf8');
  console.log(`${run.label.padEnd(16)} exit=${result.status} -> ${run.file} (${Buffer.byteLength(body, 'utf8')} bytes)`);
}
