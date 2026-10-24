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
  // Like real podman, refuses stdin that isn't a pipe (node's spawn input is a socketpair).
  writeFileSync(fakePodman, `#!/bin/sh\n[ -p /dev/stdin ] || { echo "data must be passed into stdin" >&2; exit 125; }\necho "argv: $*" >> "${podmanLog}"\nprintf 'stdin: ' >> "${podmanLog}"; cat >> "${podmanLog}"; echo >> "${podmanLog}"\n`);
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

// ---- loom's page (contract v2): ui, ui page, ui act ----------------------
// A store of its own, and a sops wrapper that records every argv and env it
// gets, so the tests can check a value typed on the page never reaches either.

const VALUES = ['pg-value-Zq7!x', 'pg-second-K3#w', 'pg-replaced-M9$v'];
let uiEnv;
let sopsLog;
const outputs = [];

const ui = (args, req, extra = {}) => {
  const r = spawnSync(process.execPath, [CLI, 'ui', ...args, '--json'],
    { input: req === undefined ? '' : JSON.stringify(req), env: { ...uiEnv, ...extra }, encoding: 'utf-8' });
  outputs.push(r.stdout, r.stderr);
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
};
const page = (path = '', query = {}) => ui(['page'], { path, query });
const act = (action, fields, path = '') => ui(['act'], { action, path, fields });
const blocksOf = (p, id) => p.sections.find((s) => s.id === id)?.blocks ?? [];
const storeNames = (p) => p.sections.filter((s) => s.id.startsWith('store'))
  .flatMap((s) => s.blocks).filter((b) => b.type === 'details').map((b) => b.summary);

before(() => {
  if (skip) return;
  const d = join(dir, 'ui');
  execFileSync('mkdir', ['-p', d]);
  sopsLog = join(d, 'sops.log');
  const wrapper = join(d, 'sops');
  writeFileSync(wrapper, `#!/bin/sh\n{ echo "argv: $*"; env; } >> "${sopsLog}"\nexec "${SOPS}" "$@"\n`);
  chmodSync(wrapper, 0o755);
  uiEnv = { ...env, LOOM_SECRETS_DIR: join(d, 'store'), LOOM_SECRETS_SOPS: wrapper };
  const r = spawnSync(process.execPath, [CLI, 'init'], { env: uiEnv, encoding: 'utf-8' });
  assert.equal(r.status, 0, r.stderr);
});

test('ui --json is a v2 manifest: a Secrets tab, a count tile with the key state, no asks', { skip }, () => {
  const m = ui([]);
  assert.equal(m.v, 2);
  assert.deepEqual(m.tab, { label: 'Secrets' });
  assert.deepEqual(m.tile, { label: 'Secrets', value: '0', detail: 'Key on this host', tone: 'ok', page: '' });
  assert.deepEqual(m.asks, []);
  assert.equal(m.sections, undefined);
  const nokey = ui([], undefined, { SOPS_AGE_KEY_FILE: join(dir, 'ui', 'no-such.key') });
  assert.equal(nokey.tile.detail, 'No key');
  assert.equal(nokey.tile.tone, 'bad');
});

test('ui page "": an intro, the Add form (text name, secret value), an empty store', { skip }, () => {
  const p = page();
  assert.equal(p.title, 'Secrets');
  assert.match(p.intro, /no way to read one back/);
  const form = blocksOf(p, 'add').find((b) => b.type === 'form');
  assert.equal(form.action, 'add');
  assert.equal(form.title, 'Add a secret');
  const [name, value] = form.fields;
  assert.equal(name.name, 'name');
  assert.equal(name.kind, 'text');
  assert.match(name.hint, /Letters, digits, dot, dash and underscore/);
  assert.equal(value.name, 'value');
  assert.equal(value.kind, 'secret');
  assert.equal('value' in value, false, 'a secret field never carries a value');
  assert.match(JSON.stringify(blocksOf(p, 'store')), /Nothing stored yet/);
});

test('ui page: an unknown path, or no readable request, is Not found', { skip }, () => {
  assert.deepEqual(page('nope'), { title: 'Not found', sections: [] });
  assert.deepEqual(page('../x'), { title: 'Not found', sections: [] });
  const r = spawnSync(process.execPath, [CLI, 'ui', 'page', '--json'], { input: 'not json', env: uiEnv, encoding: 'utf-8' });
  assert.equal(r.status, 0);
  assert.deepEqual(JSON.parse(r.stdout), { title: 'Not found', sections: [] });
});

test('ui act add stores the value from stdin JSON; the message names it, never the value', { skip }, () => {
  const r = act('add', { name: 'example-token', value: VALUES[0] });
  assert.deepEqual(r, { ok: true, message: 'example-token is encrypted and stored. Bodies pick it up the next time they start.', page: '' });
  assert.equal(act('add', { name: 'b.second', value: VALUES[1] }).ok, true);
  const got = cli(['get', 'example-token', '--reveal'], { extraEnv: { ...uiEnv, LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(got.stdout, VALUES[0]);
  assert.equal(ui([]).tile.value, '2');
});

test('ui page lists names only, each with a Replace form and a Remove button', { skip }, () => {
  const p = page();
  assert.deepEqual(storeNames(p), ['b.second', 'example-token']);
  const row = blocksOf(p, 'store').find((b) => b.summary === 'example-token');
  const [form, buttons] = row.blocks;
  assert.equal(form.type, 'form');
  assert.equal(form.action, 'replace');
  assert.equal(form.title, 'Replace example-token');
  assert.deepEqual(form.hidden, { name: 'example-token' });
  assert.deepEqual(form.fields.map((f) => [f.name, f.kind, 'value' in f]), [['value', 'secret', false]]);
  assert.deepEqual(buttons, { type: 'buttons', items: [{ action: 'remove', label: 'Remove', tone: 'danger', fields: { name: 'example-token' } }] });
});

test('ui act add refuses an existing name and points to Replace', { skip }, () => {
  const r = act('add', { name: 'example-token', value: 'something-else' });
  assert.equal(r.ok, false);
  assert.match(r.message, /example-token already exists.*Replace/);
  const got = cli(['get', 'example-token', '--reveal'], { extraEnv: { ...uiEnv, LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(got.stdout, VALUES[0], 'unchanged');
});

test('ui act replace overwrites an existing name, and refuses a missing one', { skip }, () => {
  const r = act('replace', { name: 'example-token', value: VALUES[2] });
  assert.equal(r.ok, true, r.message);
  assert.match(r.message, /^example-token is replaced/);
  const got = cli(['get', 'example-token', '--reveal'], { extraEnv: { ...uiEnv, LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(got.stdout, VALUES[2]);
  const missing = act('replace', { name: 'not-there', value: 'x-value-1' });
  assert.equal(missing.ok, false);
  assert.match(missing.message, /no secret named not-there/);
  assert.deepEqual(storeNames(page()), ['b.second', 'example-token']);
});

test('ui act refuses bad names (without echoing them), empty and oversized values', { skip }, () => {
  for (const bad of ['../x', '-x', 'a b', '', 'x'.repeat(65), 'leaked-in-the-name field?']) {
    const r = act('add', { name: bad, value: 'some-value' });
    assert.equal(r.ok, false, bad);
    assert.match(r.message, /not a secret name/);
    if (bad) assert.ok(!r.message.includes(bad), 'a bad name is not echoed');
  }
  assert.equal(act('add', { value: 'v' }).ok, false);
  assert.equal(act('add', { name: 7, value: 'v' }).ok, false);
  for (const value of ['', undefined, 42, { a: 1 }]) {
    const r = act('add', { name: 'empty-one', value });
    assert.equal(r.ok, false);
    assert.match(r.message, /empty/);
  }
  assert.equal(act('replace', { name: 'example-token', value: '' }).ok, false);
  const big = act('add', { name: 'big-one', value: 'y'.repeat(64 * 1024 + 1) });
  assert.equal(big.ok, false);
  assert.match(big.message, /over 64 KB/);
  assert.equal(act('add', { name: 'just-fits', value: 'z'.repeat(64 * 1024) }).ok, true);
  assert.equal(act('remove', { name: 'just-fits' }).ok, true);
  assert.deepEqual(storeNames(page()), ['b.second', 'example-token']);
});

test('ui act has no read action, and refuses unknown actions and unreadable requests', { skip }, () => {
  for (const action of ['get', 'reveal', 'read', 'show', 'podman', 'toString', '__proto__', undefined]) {
    const r = act(action, { name: 'example-token' });
    assert.equal(r.ok, false, String(action));
    assert.match(r.message, /no such action/);
  }
  const r = spawnSync(process.execPath, [CLI, 'ui', 'act', '--json'], { input: '[1]', env: uiEnv, encoding: 'utf-8' });
  assert.equal(r.status, 0);
  assert.equal(JSON.parse(r.stdout).ok, false);
});

test('ui act remove removes, and refuses a missing name', { skip }, () => {
  const r = act('remove', { name: 'b.second' });
  assert.deepEqual(r, { ok: true, message: 'b.second is removed from the store.', page: '' });
  assert.deepEqual(storeNames(page()), ['example-token']);
  const again = act('remove', { name: 'b.second' });
  assert.equal(again.ok, false);
  assert.match(again.message, /no secret named b.second/);
});

test('names that match Object.prototype keys are ordinary names', { skip }, () => {
  // `name in data` would see an inherited constructor and call it taken.
  assert.equal(act('add', { name: 'constructor', value: 'v1' }).ok, true);
  assert.equal(act('replace', { name: 'toString', value: 'v2' }).ok, false);
  assert.equal(act('remove', { name: 'constructor' }).ok, true);
  assert.equal(act('remove', { name: 'hasOwnProperty' }).ok, false);
});

test('a big store stays inside loom\'s limits: 20 rows a section, 10 sections, parts beyond that', { skip }, () => {
  // Fake names straight into a scratch store: names() reads keys without decrypting.
  const d = join(dir, 'ui-big');
  execFileSync('mkdir', ['-p', d]);
  const doc = { sops: {} };
  for (let i = 0; i < 205; i++) doc[`n${String(i).padStart(3, '0')}`] = 'ENC[...]';
  writeFileSync(join(d, 'store.sops.json'), JSON.stringify(doc));
  const extra = { LOOM_SECRETS_DIR: d };
  const p1 = ui(['page'], { path: '', query: {} }, extra);
  assert.ok(p1.sections.length <= 10);
  for (const s of p1.sections) assert.ok(s.blocks.length <= 20);
  assert.equal(storeNames(p1).length, 160);
  const parts = p1.sections.find((s) => s.id === 'parts');
  assert.equal(parts.side, true);
  assert.deepEqual(parts.blocks[0].options.map((o) => o.value), ['', '2']);
  const p2 = ui(['page'], { path: '', query: { part: '2' } }, extra);
  assert.equal(storeNames(p2).length, 45);
  assert.equal(storeNames(p2)[0], 'n160');
  assert.equal(storeNames(ui(['page'], { path: '', query: { part: '99' } }, extra))[0], 'n000');
  assert.ok(Buffer.byteLength(JSON.stringify(p1)) < 512 * 1024);
});

test('no ui output, and no sops argv or env, ever held a value typed on the page', { skip }, () => {
  outputs.push(JSON.stringify(ui([])), JSON.stringify(page()));
  const all = outputs.join('\n');
  for (const v of VALUES) assert.ok(!all.includes(v), `a value reached ui output: ${v.slice(0, 3)}...`);
  const log = readFileSync(sopsLog, 'utf-8');
  assert.match(log, /argv: --encrypt/, 'the wrapper saw the writes');
  for (const v of VALUES) assert.ok(!log.includes(v), 'a value reached sops argv or env');
  const raw = readFileSync(join(uiEnv.LOOM_SECRETS_DIR, 'store.sops.json'), 'utf-8');
  for (const v of VALUES) assert.ok(!raw.includes(v), 'plaintext on disk');
  const leftovers = execFileSync('ls', ['-a', uiEnv.LOOM_SECRETS_DIR], { encoding: 'utf-8' }).trim().split('\n').sort();
  assert.deepEqual(leftovers, ['.', '..', 'age.key', 'store.sops.json'], 'no temp or lock files left behind');
});

// ---- loom's bundle: bundle export / bundle import ------------------------
// Store A exports to the owner's recipient R; an empty store B (a "fresh
// machine" with no key yet) imports with R's identity. Wrappers around sops
// and age record every argv and env they get, so no value may appear there.

const AGE = process.env.LOOM_SECRETS_AGE || which('age');
const bskip = skip || (!AGE ? 'age not installed' : false);
const BUNDLE_VALUES = { 'api-token': 'bx-value-Qw8!z', 'db.pass': 'bx-second-T4#k', 'multi-line': 'line one\nline two\n' };
let bdir;
let toolLog;
let aEnv;
let ownerKey;
let ownerRecipient;
let part;

const bcli = (args, extra, input) => {
  const r = spawnSync(process.execPath, [CLI, ...args], { input: input ?? '', env: { ...extra }, encoding: 'utf-8' });
  return r;
};
const storeEnv = (name) => ({ ...aEnv, LOOM_SECRETS_DIR: join(bdir, name) });
const reveal = (e, name) => bcli(['get', name, '--reveal'], { ...e, LOOM_SECRETS_ALLOW_GET: '1' }).stdout;
const keygenTo = (file) => { execFileSync(KEYGEN, ['-o', file], { stdio: 'ignore' }); return execFileSync(KEYGEN, ['-y', file], { encoding: 'utf-8' }).trim(); };

before(() => {
  if (bskip) return;
  bdir = join(dir, 'bundle');
  execFileSync('mkdir', ['-p', bdir]);
  toolLog = join(bdir, 'tools.log');
  const wrap = (name, real) => {
    const w = join(bdir, `${name}-wrapper`);
    writeFileSync(w, `#!/bin/sh\n{ echo "${name} argv: $*"; env; } >> "${toolLog}"\nexec "${real}" "$@"\n`);
    chmodSync(w, 0o755);
    return w;
  };
  ownerKey = join(bdir, 'owner.key');
  ownerRecipient = keygenTo(ownerKey);
  aEnv = { ...env, LOOM_SECRETS_DIR: join(bdir, 'a'), LOOM_SECRETS_SOPS: wrap('sops', SOPS), LOOM_SECRETS_AGE: wrap('age', AGE) };
  assert.equal(bcli(['init'], aEnv).status, 0);
  for (const [n, v] of Object.entries(BUNDLE_VALUES)) assert.equal(bcli(['add', n], aEnv, v + '\n').status, 0);
});

test('bundle export refuses with no recipients, or a malformed one (never echoing it)', { skip: bskip }, () => {
  for (const extra of [{}, { LOOM_EXPORT_RECIPIENTS: '' }, { LOOM_EXPORT_RECIPIENTS: ' , ' }]) {
    const r = bcli(['bundle', 'export'], { ...aEnv, ...extra });
    assert.equal(r.status, 2);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /LOOM_EXPORT_RECIPIENTS is empty/);
  }
  const secretKey = readFileSync(ownerKey, 'utf-8').match(/AGE-SECRET-KEY-\S+/)[0];
  for (const bad of ['not-a-key', 'age1short', secretKey]) {
    const r = bcli(['bundle', 'export'], { ...aEnv, LOOM_EXPORT_RECIPIENTS: `${ownerRecipient},${bad}` });
    assert.equal(r.status, 2, bad);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /recipient 2 .* isn't an age recipient/);
    assert.ok(!r.stderr.includes(bad), 'a malformed recipient is not echoed');
  }
  assert.match(bcli(['bundle', 'export'], { ...aEnv, LOOM_EXPORT_RECIPIENTS: secretKey }).stderr, /looks like a private key/);
});

test('bundle export writes an age part to the recipients; it holds no plaintext name or value', { skip: bskip }, () => {
  const r = bcli(['bundle', 'export'], { ...aEnv, LOOM_EXPORT_RECIPIENTS: ownerRecipient });
  assert.equal(r.status, 0, r.stderr);
  part = r.stdout;
  assert.match(part, /^-----BEGIN AGE ENCRYPTED FILE-----\n/);
  for (const v of Object.values(BUNDLE_VALUES)) assert.ok(!part.includes(v.trim().split('\n')[0]), 'plaintext value in the part');
  for (const n of Object.keys(BUNDLE_VALUES)) assert.ok(!part.includes(n), 'plaintext name in the part');
  assert.match(r.stderr, /exported 3 secret\(s\), encrypted to 1 recipient/);
  for (const v of Object.values(BUNDLE_VALUES)) assert.ok(!r.stderr.includes(v.trim().split('\n')[0]));
  // It opens with the owner's identity, as the documented format.
  const doc = JSON.parse(execFileSync(AGE, ['-d', '-i', ownerKey], { input: part, encoding: 'utf-8' }));
  assert.equal(doc.format, 'loom-secrets/1');
  assert.deepEqual(Object.keys(doc.secrets), Object.keys(BUNDLE_VALUES).sort());
  // ...and not with the store's own key: that's the box key that may be gone.
  const own = spawnSync(AGE, ['-d', '-i', join(bdir, 'a', 'age.key')], { input: part });
  assert.notEqual(own.status, 0);
});

test('bundle export with no store is a valid empty part', { skip: bskip }, () => {
  const e = storeEnv('never-made');
  const r = bcli(['bundle', 'export'], { ...e, LOOM_EXPORT_RECIPIENTS: ownerRecipient });
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(JSON.parse(execFileSync(AGE, ['-d', '-i', ownerKey], { input: r.stdout, encoding: 'utf-8' })),
    { format: 'loom-secrets/1', secrets: {} });
  assert.equal(existsSync(join(bdir, 'never-made')), false, 'export creates nothing');
});

test('bundle import round trip: a fresh store B gets every name and value, under its own new key', { skip: bskip }, () => {
  const b = storeEnv('b');
  const r = bcli(['bundle', 'import'], { ...b, LOOM_IMPORT_IDENTITY: ownerKey }, part);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, '');
  assert.match(r.stderr, /imported 3 secret\(s\)/);
  assert.equal(statSync(join(bdir, 'b')).mode & 0o777, 0o700);
  const bKey = join(bdir, 'b', 'age.key');
  assert.equal(statSync(bKey).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(bcli(['list', '--json'], b).stdout), Object.keys(BUNDLE_VALUES).sort());
  for (const [n, v] of Object.entries(BUNDLE_VALUES)) assert.equal(reveal(b, n), v, n);
  // ac-sec-import-rekeys: B's store is encrypted to B's key, not the owner's or A's.
  const doc = JSON.parse(readFileSync(join(bdir, 'b', 'store.sops.json'), 'utf-8'));
  const bRecipient = execFileSync(KEYGEN, ['-y', bKey], { encoding: 'utf-8' }).trim();
  assert.deepEqual(doc.sops.age.map((x) => x.recipient), [bRecipient]);
  assert.notEqual(bRecipient, ownerRecipient);
  const withOwner = spawnSync(SOPS, ['--decrypt', join(bdir, 'b', 'store.sops.json')], { env: { ...env, SOPS_AGE_KEY_FILE: ownerKey } });
  assert.notEqual(withOwner.status, 0, "the owner's key doesn't open B's store");
  const raw = readFileSync(join(bdir, 'b', 'store.sops.json'), 'utf-8');
  for (const v of Object.values(BUNDLE_VALUES)) assert.ok(!raw.includes(v.trim().split('\n')[0]), 'plaintext on disk');
  const leftovers = execFileSync('ls', ['-a', join(bdir, 'b')], { encoding: 'utf-8' }).trim().split('\n').sort();
  assert.deepEqual(leftovers, ['.', '..', 'age.key', 'store.sops.json'], 'no temp or lock files left behind');
});

test('bundle import refuses over a store that holds secrets; --force replaces it', { skip: bskip }, () => {
  const b = storeEnv('b');
  assert.equal(bcli(['add', 'only-on-b'], b, 'b-local-value').status, 0);
  const r = bcli(['bundle', 'import'], { ...b, LOOM_IMPORT_IDENTITY: ownerKey }, part);
  assert.equal(r.status, 3);
  assert.match(r.stderr, /already holds 4 secret\(s\).*--force/);
  assert.ok(JSON.parse(bcli(['list', '--json'], b).stdout).includes('only-on-b'), 'untouched');
  const keyBefore = readFileSync(join(bdir, 'b', 'age.key'), 'utf-8');
  const f = bcli(['bundle', 'import', '--force'], { ...b, LOOM_IMPORT_IDENTITY: ownerKey }, part);
  assert.equal(f.status, 0, f.stderr);
  assert.deepEqual(JSON.parse(bcli(['list', '--json'], b).stdout), Object.keys(BUNDLE_VALUES).sort());
  assert.equal(readFileSync(join(bdir, 'b', 'age.key'), 'utf-8'), keyBefore, 'keeps this machine\'s key');
});

test('bundle import into an empty initialised store needs no --force', { skip: bskip }, () => {
  const e = storeEnv('c');
  assert.equal(bcli(['init'], e).status, 0);
  const r = bcli(['bundle', 'import'], { ...e, LOOM_IMPORT_IDENTITY: ownerKey }, part);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(reveal(e, 'api-token'), BUNDLE_VALUES['api-token']);
});

test('bundle import fails cleanly with the wrong identity, and writes nothing', { skip: bskip }, () => {
  const wrong = join(bdir, 'wrong.key');
  keygenTo(wrong);
  const e = storeEnv('d');
  const r = bcli(['bundle', 'import'], { ...e, LOOM_IMPORT_IDENTITY: wrong }, part);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /doesn't decrypt with LOOM_IMPORT_IDENTITY/);
  assert.equal(existsSync(join(bdir, 'd')), false, 'no key or store created');
  const junk = bcli(['bundle', 'import'], { ...e, LOOM_IMPORT_IDENTITY: ownerKey }, 'not a part');
  assert.equal(junk.status, 1);
  assert.equal(existsSync(join(bdir, 'd')), false);
});

test('bundle import refuses with no identity, a missing identity file, or no part', { skip: bskip }, () => {
  const e = storeEnv('e');
  const none = bcli(['bundle', 'import'], e, part);
  assert.equal(none.status, 2);
  assert.match(none.stderr, /LOOM_IMPORT_IDENTITY is empty/);
  const missing = bcli(['bundle', 'import'], { ...e, LOOM_IMPORT_IDENTITY: join(bdir, 'no-such.key') }, part);
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /names no file/);
  const empty = bcli(['bundle', 'import'], { ...e, LOOM_IMPORT_IDENTITY: ownerKey }, '');
  assert.equal(empty.status, 2);
  assert.match(empty.stderr, /no part on stdin/);
  assert.equal(existsSync(join(bdir, 'e')), false);
});

test('bundle with no verb, or an unknown one, or bare export/import, is exit 2', { skip: bskip }, () => {
  for (const args of [['bundle'], ['bundle', 'dump'], ['bundle', 'export', 'extra'], ['export'], ['import']]) {
    const r = bcli(args, { ...aEnv, LOOM_EXPORT_RECIPIENTS: ownerRecipient });
    assert.equal(r.status, 2, args.join(' '));
    assert.equal(r.stdout.includes('BEGIN AGE'), false);
  }
  assert.equal(bcli(['bundle', 'export', '--force'], { ...aEnv, LOOM_EXPORT_RECIPIENTS: ownerRecipient }).status, 2);
});

test('no value ever reached sops or age argv or env during export and import', { skip: bskip }, () => {
  const log = readFileSync(toolLog, 'utf-8');
  assert.match(log, /age argv: -e -a -r age1/, 'the wrapper saw the export');
  assert.match(log, /age argv: -d -i /, 'the wrapper saw the import');
  assert.match(log, /sops argv: --encrypt/);
  for (const v of Object.values(BUNDLE_VALUES)) {
    for (const line of v.split('\n').filter(Boolean)) assert.ok(!log.includes(line), `a value reached argv or env: ${line.slice(0, 3)}...`);
  }
});
