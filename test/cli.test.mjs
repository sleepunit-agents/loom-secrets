// Runs the real CLI as a subprocess against real sops + age, with a throwaway
// key in a temp dir. Skips if the binaries aren't installed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, chmodSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
const which = (b) => { try { return execFileSync('sh', ['-c', `command -v ${b}`], { encoding: 'utf-8' }).trim(); } catch { return ''; } };
const SOPS = process.env.LOOM_SECRETS_SOPS || which('sops');
const KEYGEN = process.env.LOOM_SECRETS_AGE_KEYGEN || which('age-keygen');
const skip = !SOPS || !KEYGEN ? 'sops/age-keygen not installed' : false;

let dir;
let env;
let podmanLog;

before(() => {
  dir = mkdtempSync(join(tmpdir(), 'loom-secrets-'));
  podmanLog = join(dir, 'podman.log');
  const fakePodman = join(dir, 'podman');
  // Records argv and stdin, the way `podman secret create --replace NAME -` gets them.
  writeFileSync(fakePodman, `#!/bin/sh\necho "argv: $*" >> "${podmanLog}"\nprintf 'stdin: ' >> "${podmanLog}"; cat >> "${podmanLog}"; echo >> "${podmanLog}"\n`);
  chmodSync(fakePodman, 0o755);
  env = {
    PATH: process.env.PATH,
    HOME: dir,
    LOOM_SECRETS_DIR: join(dir, 'store'),
    LOOM_SECRETS_SOPS: SOPS,
    LOOM_SECRETS_AGE_KEYGEN: KEYGEN,
    LOOM_SECRETS_PODMAN: fakePodman,
  };
});
after(() => rmSync(dir, { recursive: true, force: true }));

const cli = (args, { input, extraEnv } = {}) =>
  spawnSync(process.execPath, [CLI, ...args], { input: input ?? '', env: { ...env, ...extraEnv }, encoding: 'utf-8' });

test('init makes a 0600 key in a 0700 dir and an empty encrypted store', { skip }, () => {
  const r = cli(['init']);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(statSync(env.LOOM_SECRETS_DIR).mode & 0o777, 0o700);
  assert.equal(statSync(join(env.LOOM_SECRETS_DIR, 'age.key')).mode & 0o777, 0o600);
  assert.ok(existsSync(join(env.LOOM_SECRETS_DIR, 'store.sops.json')));
  assert.equal(cli(['list']).stdout, '');
});

test('add reads the value from stdin; the file on disk never holds it', { skip }, () => {
  const r = cli(['add', 'google-pass'], { input: 'hunter22-correct-horse\n' });
  assert.equal(r.status, 0, r.stderr);
  const raw = readFileSync(join(env.LOOM_SECRETS_DIR, 'store.sops.json'), 'utf-8');
  assert.ok(!raw.includes('hunter22'), 'plaintext value on disk');
  assert.ok(raw.includes('google-pass'), 'names stay readable');
});

test('a value in argv is refused, and nothing is stored', { skip }, () => {
  const r = cli(['add', 'leaky', 'hunter22']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /refusing a value in argv/);
  assert.deepEqual(JSON.parse(cli(['list', '--json']).stdout), ['google-pass']);
});

test('add refuses to overwrite without --force; --force replaces', { skip }, () => {
  assert.equal(cli(['add', 'google-pass'], { input: 'other' }).status, 3);
  assert.equal(cli(['add', 'google-pass', '--force'], { input: 'v2' }).status, 0);
  const got = cli(['get', 'google-pass', '--reveal'], { extraEnv: { LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(got.stdout, 'v2');
});

test('list never decrypts: it works with the key gone', { skip }, () => {
  const key = join(env.LOOM_SECRETS_DIR, 'age.key');
  const saved = readFileSync(key);
  rmSync(key);
  try {
    const r = cli(['list']);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout, 'google-pass\n');
  } finally {
    writeFileSync(key, saved, { mode: 0o600 });
  }
});

test('get refuses a body by default (no terminal, no host allowance), and without --reveal', { skip }, () => {
  const body = cli(['get', 'google-pass', '--reveal']);
  assert.equal(body.status, 4);
  assert.equal(body.stdout, '');
  assert.match(body.stderr, /injected into its runtime/);
  assert.equal(cli(['get', 'google-pass'], { extraEnv: { LOOM_SECRETS_ALLOW_GET: '1' } }).status, 2);
});

test('podman is gated like get --reveal (else LOOM_SECRETS_PODMAN=cat would print the value)', { skip }, () => {
  const r = cli(['podman', 'google-pass', 'x'], { extraEnv: { LOOM_SECRETS_PODMAN: 'cat' } });
  assert.equal(r.status, 4);
  assert.equal(r.stdout, '');
});

test('podman injects the value over stdin, never argv, and prints nothing', { skip }, () => {
  const r = cli(['podman', 'google-pass', 'art-google-pass'], { extraEnv: { LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, '');
  const log = readFileSync(podmanLog, 'utf-8');
  assert.match(log, /argv: secret create --replace art-google-pass -\n/);
  assert.match(log, /stdin: v2\n/);
  assert.ok(!/argv:.*v2/.test(log), 'value reached podman argv');
});

test('rm removes; unknown names are exit 3; bad names are exit 2', { skip }, () => {
  assert.equal(cli(['rm', 'google-pass']).status, 0);
  assert.equal(cli(['list']).stdout, '');
  assert.equal(cli(['rm', 'google-pass']).status, 3);
  for (const bad of ['../x', '-x', 'a b', '']) assert.equal(cli(['rm', bad]).status, 2, bad);
});

test('an empty value is refused', { skip }, () => {
  assert.equal(cli(['add', 'empty'], { input: '' }).status, 2);
});

test('the value never shows in any argv while the CLI runs', { skip }, () => {
  // sops and podman get the value on stdin only; checked above for podman.
  // For sops: the encrypt call's argv is fixed, and the plaintext goes via /dev/stdin.
  const src = readFileSync(CLI, 'utf-8');
  assert.match(src, /'--filename-override', STORE, '\/dev\/stdin'\]/);
});
