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
    TZ: 'America/Chicago',  // the box's local time, which the page's times are in
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
const storeNames = (p) => p.sections.filter((s) => s.id === 'store')
  .flatMap((s) => s.blocks).filter((b) => b.type === 'panel').flatMap((b) => b.rows.map((r) => r.label));
const rowsOf = (p, id) => blocksOf(p, id).filter((b) => b.type === 'panel').flatMap((b) => b.rows);
// The whole store, as a list: the index is a summary; every name is a tap away on list?of=all.
const allPage = (query = {}) => page('list', { of: 'all', ...query });
// The store's own record (set, removed, read on loom's machine), beside the requests' events.
const STORE_EVENTS = ['set', 'removed', 'host-read'];

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
  assert.deepEqual(m.tab, { label: 'Secrets', kind: 'setting' });
  assert.deepEqual(m.agentTab, { label: 'Secrets' }, "each agent's grants and requests are on its own tab");
  assert.deepEqual(m.tile, { label: 'Secrets', value: '0', detail: 'Key on this host', tone: 'ok', page: '' });
  assert.deepEqual(m.asks, []);
  assert.equal(m.sections, undefined);
  const nokey = ui([], undefined, { SOPS_AGE_KEY_FILE: join(dir, 'ui', 'no-such.key') });
  assert.equal(nokey.tile.detail, 'No key');
  assert.equal(nokey.tile.tone, 'bad');
});

test('ui page "": an intro, what needs a look, the store as groups, Add a secret (a row whose sheet takes a text name and a secret value)', { skip }, () => {
  const p = page();
  assert.equal(p.title, 'Secrets');
  assert.match(p.intro, /no way to read one back/);
  assert.deepEqual(p.sections.map((s) => s.id), ['look', 'groups', 'add', 'policy']);
  const [addRow] = rowsOf(p, 'add');
  assert.equal(addRow.label, 'Add a secret');
  const form = addRow.edit;
  assert.equal(form.action, 'add');
  const [name, value] = form.fields;
  assert.equal(name.name, 'name');
  assert.equal(name.kind, 'text');
  assert.match(name.hint, /Letters, digits, dot, dash and underscore/);
  assert.equal(value.name, 'value');
  assert.equal(value.kind, 'secret');
  assert.equal('value' in value, false, 'a secret field never carries a value');
  assert.match(JSON.stringify(blocksOf(p, 'groups')), /Nothing stored yet/);
  assert.match(JSON.stringify(blocksOf(allPage(), 'store')), /None/);
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

test('ui page lists names only, each a row to its own page: a Replace form and a Remove that asks first', { skip }, () => {
  const p = allPage();
  assert.deepEqual(storeNames(p), ['b.second', 'example-token']);
  const row = rowsOf(p, 'store')[1];
  assert.deepEqual([row.label, row.value, row.detail, row.page], ['example-token', 'Asks you first', "Last read on loom's machine just now", 'secret?name=example-token']);
  const one = page('secret', { name: 'example-token' });
  assert.equal(one.title, 'example-token');
  const value = rowsOf(one, 'secret')[0];
  assert.equal(value.label, 'Value');
  assert.match(value.value, /^Hidden/);
  const form = value.edit;
  assert.equal(form.action, 'replace');
  assert.deepEqual(form.hidden, { name: 'example-token' });
  assert.deepEqual(form.fields.map((f) => [f.name, f.kind, 'value' in f]), [['value', 'secret', false]]);
  const remove = rowsOf(one, 'more').find((r) => r.label === 'Remove').act;
  assert.deepEqual([remove.action, remove.label, remove.tone, remove.fields.name, typeof remove.confirm], ['remove', 'Remove', 'danger', 'example-token', 'string']);
  assert.deepEqual(page('secret', { name: 'not-there' }), { title: 'Not found', sections: [] });
  assert.deepEqual(page('secret', { name: '../x' }), { title: 'Not found', sections: [] });
  assert.deepEqual(page('secret/example-token'), { title: 'Not found', sections: [] });
  // Names with capitals (loom's page paths are lowercase) ride in the query.
  assert.equal(act('add', { name: 'Upper.CASE', value: 'v-up' }).ok, true);
  assert.equal(rowsOf(allPage(), 'store').find((r) => r.label === 'Upper.CASE').page, 'secret?name=Upper.CASE');
  assert.equal(page('secret', { name: 'Upper.CASE' }).title, 'Upper.CASE');
  assert.equal(act('remove', { name: 'Upper.CASE' }).ok, true);
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
  assert.deepEqual(storeNames(allPage()), ['b.second', 'example-token']);
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
  assert.deepEqual(storeNames(allPage()), ['b.second', 'example-token']);
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
  assert.deepEqual(storeNames(allPage()), ['example-token']);
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

test('a big store stays inside loom\'s limits: 200 rows a list, parts beyond that', { skip }, () => {
  // Fake names straight into a scratch store: names() reads keys without decrypting.
  const d = join(dir, 'ui-big');
  execFileSync('mkdir', ['-p', d]);
  const doc = { sops: {} };
  for (let i = 0; i < 205; i++) doc[`n${String(i).padStart(3, '0')}`] = 'ENC[...]';
  writeFileSync(join(d, 'store.sops.json'), JSON.stringify(doc));
  const extra = { LOOM_SECRETS_DIR: d };
  const p1 = ui(['page'], { path: 'list', query: { of: 'all' } }, extra);
  assert.ok(p1.sections.length <= 10);
  for (const s of p1.sections) assert.ok(s.blocks.length <= 20);
  assert.equal(storeNames(p1).length, 200);
  const parts = p1.sections.find((s) => s.id === 'parts');
  assert.equal(parts.side, true);
  assert.deepEqual(parts.blocks[0].options.map((o) => o.value), ['', '2']);
  const p2 = ui(['page'], { path: 'list', query: { of: 'all', part: '2' } }, extra);
  assert.equal(storeNames(p2).length, 5);
  assert.equal(storeNames(p2)[0], 'n200');
  assert.equal(storeNames(ui(['page'], { path: 'list', query: { of: 'all', part: '99' } }, extra))[0], 'n000');
  assert.ok(Buffer.byteLength(JSON.stringify(p1)) < 512 * 1024);
});

test('no ui output, and no sops argv or env, ever held a value typed on the page', { skip }, () => {
  outputs.push(JSON.stringify(ui([])), JSON.stringify(page()), JSON.stringify(allPage()));
  for (const name of storeNames(allPage())) outputs.push(JSON.stringify(page('secret', { name })));
  const all = outputs.join('\n');
  for (const v of VALUES) assert.ok(!all.includes(v), `a value reached ui output: ${v.slice(0, 3)}...`);
  const log = readFileSync(sopsLog, 'utf-8');
  assert.match(log, /argv: --encrypt/, 'the wrapper saw the writes');
  for (const v of VALUES) assert.ok(!log.includes(v), 'a value reached sops argv or env');
  const raw = readFileSync(join(uiEnv.LOOM_SECRETS_DIR, 'store.sops.json'), 'utf-8');
  for (const v of VALUES) assert.ok(!raw.includes(v), 'plaintext on disk');
  const leftovers = execFileSync('ls', ['-a', uiEnv.LOOM_SECRETS_DIR], { encoding: 'utf-8' }).trim().split('\n').sort();
  assert.deepEqual(leftovers, ['.', '..', 'age.key', 'audit.jsonl', 'store.sops.json'], 'no temp or lock files left behind');
  // The record says when each was set or removed: names, never a value.
  const record = readFileSync(join(uiEnv.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8');
  assert.match(record, /"event":"set","secret":"example-token","how":"add"/);
  assert.match(record, /"event":"set","secret":"example-token","how":"replace"/);
  assert.match(record, /"event":"removed","secret":"b.second"/);
  for (const v of VALUES) assert.ok(!record.includes(v), 'a value reached the record');
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
  assert.deepEqual(leftovers, ['.', '..', 'age.key', 'audit.jsonl', 'store.sops.json'], 'no temp or lock files left behind');
  // The record says when each was set or removed: names, never a value.
  const record = readFileSync(join(uiEnv.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8');
  assert.match(record, /"event":"set","secret":"example-token","how":"add"/);
  assert.match(record, /"event":"set","secret":"example-token","how":"replace"/);
  assert.match(record, /"event":"removed","secret":"b.second"/);
  for (const v of VALUES) assert.ok(!record.includes(v), 'a value reached the record');
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

// ---- requests (README, "Requests") ------------------------------------------
// A house asks for a secret it doesn't carry. The policy grants it (auto),
// refuses it (never), or asks the owner (the default): a card with Allow and
// Deny on loom's page. A grant is one house's, for minutes, and `get` reads
// the value for that house only.

const api = (caller, argv) => {
  const r = cli(['api', '--json'], { input: JSON.stringify({ caller, path: 'run', body: { argv } }) });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
};
const house = (h, agent = 'art') => ({ kind: 'agent', agent, house: h });

test('requests: ask by default, the owner allows on the page, and only that house reads it', { skip }, () => {
  cli(['init']);
  cli(['add', 'onterris-gh'], { input: 'ghp_ONTERRIS_VALUE' });
  // Not a house: an agent's plain token, the owner, a box: refused.
  for (const c of [{ kind: 'agent', agent: 'art' }, { kind: 'owner' }, { kind: 'piece', subject: 'thor' }]) {
    assert.equal(api(c, ['request', 'onterris-gh', '--why', 'x']).status, 403);
  }
  assert.equal(api(house('h-7'), ['request', 'nope', '--why', 'x']).status, 404);
  assert.match(api(house('h-7'), ['request', 'onterris-gh']).body.stderr, /--why/);
  const asked = api(house('h-7'), ['request', 'onterris-gh', '--why', 'push the fix for onterris/pond#212 <b>now</b>']);
  assert.match(asked.body.stdout, /asked the owner/);
  // Asking again is the same request: one card.
  api(house('h-7'), ['request', 'onterris-gh', '--why', 'again']);
  const m = JSON.parse(cli(['ui', '--json']).stdout);
  assert.equal(m.asks.length, 1);
  const ask = m.asks[0];
  assert.equal(ask.text, 'Art asks for onterris-gh');
  assert.equal(ask.page, 'secret?name=onterris-gh', "the card opens the secret's own page");
  // No house id leads it: how long, and the house's reason as written.
  assert.match(ask.meta, /^For \d+ min: \u201cpush the fix for onterris\/pond#212 b now \/b\u201d$/);
  assert.match(ask.actions[1].confirm, /^Every house of Art gets onterris-gh without asking, 8 hours at a time,/);
  assert.deepEqual(ask.actions.map((a) => a.action), ['grant', 'always', 'deny']);
  // Waiting: no value yet.
  assert.equal(api(house('h-7'), ['get', 'onterris-gh']).status, 403);
  const act = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'grant', fields: ask.actions[0].fields }) }).stdout);
  assert.equal(act.ok, true, act.message);
  assert.match(act.message, /^Allowed: Art's onterris-gh, for \d+ min\.$/);
  assert.equal(JSON.parse(cli(['ui', '--json']).stdout).asks.length, 0);
  // loom's Inbox: the card was a permission, and what was answered is its history.
  assert.equal(ask.kind, 'permission');
  const after = JSON.parse(cli(['ui', '--json']).stdout).answered;
  assert.equal(after.length, 1);
  assert.match(after[0].text, /^Art asked for onterris-gh/);
  assert.equal(after[0].outcome, `Allowed for ${ask.actions[0].label.match(/\d+/)[0]} min.`);
  const got = api(house('h-7'), ['get', 'onterris-gh']);
  assert.equal(got.body.stdout, 'ghp_ONTERRIS_VALUE');
  // Another house of the same agent has nothing.
  assert.equal(api(house('h-8'), ['get', 'onterris-gh']).status, 403);
  // The page never carries the value; the owner can revoke.
  const page = cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }), extraEnv: { LOOM_SCOPE: 'art' } }).stdout;
  assert.ok(!page.includes('ghp_ONTERRIS_VALUE'));
  const live = JSON.parse(page).sections.find((s) => s.id === 'grants').blocks[0].rows[0];
  // A live grant: a row saying when it runs out, in the box's 12-hour local time; no house id, no UTC; the house's reason whole.
  assert.equal(live.label, "Art's house \u00b7 onterris-gh");
  assert.match(live.value, /^Can read it until \d{1,2}:\d{2} [AP]M$/);
  assert.equal(live.detail, '\u201cpush the fix for onterris/pond#212 b now /b\u201d');
  assert.doesNotMatch(`${live.label} ${live.value}`, /h-7|UTC/);
  assert.equal(live.act.confirm, "That house won't be able to read onterris-gh again.");
  // The household's page doesn't list them: each agent is a group, and its group links its tab.
  const home = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }) }).stdout);
  assert.equal(home.sections.find((s) => s.id === 'requests'), undefined);
  const artRow = home.sections.find((s) => s.id === 'groups').blocks[0].rows.find((r) => r.agent === 'art');
  assert.deepEqual([artRow.label, artRow.page], ['Art', 'list?of=agent%3Aart']);
  const artGroup = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'list', query: { of: 'agent:art' } }) }).stdout);
  assert.equal(artGroup.sections.find((s) => s.id === 'agent').blocks[0].rows[0].page, 'agent:art');
  // An agent's tab has no household list.
  assert.deepEqual(JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'list', query: { of: 'all' } }), extraEnv: { LOOM_SCOPE: 'art' } }).stdout), { title: 'Not found', sections: [] });
  // From mark's tab, art's request is not mark's to revoke.
  const other = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'revoke', fields: live.act.fields }), extraEnv: { LOOM_SCOPE: 'mark' } }).stdout);
  assert.equal(other.ok, false);
  assert.equal(JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }), extraEnv: { LOOM_SCOPE: 'mark' } }).stdout)
    .sections.find((s) => s.id === 'requests').blocks[0].type, 'text', "mark's tab has none of art's");
  assert.equal(live.act.action, 'revoke');
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'revoke', fields: live.act.fields }) });
  assert.equal(api(house('h-7'), ['get', 'onterris-gh']).status, 403);
  // Every step is on the record.
  const audit = readFileSync(join(env.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l).event)
    .filter((e) => !STORE_EVENTS.includes(e));
  assert.deepEqual(audit, ['request', 'refused-read', 'grant', 'read', 'refused-read', 'revoke', 'refused-read']);
  assert.ok(!readFileSync(join(env.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8').includes('ghp_ONTERRIS_VALUE'));
});

test('requests: the policy grants (auto, for the agents it names), refuses (never), and caps the minutes', { skip }, () => {
  cli(['add', 'mark-discord'], { input: 'DISCORD' });
  cli(['add', 'root-ssh'], { input: 'SSH' });
  writeFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), JSON.stringify({ v: 1, default: 'ask', secrets: {
    'mark-discord': { grant: 'auto', agents: ['mark'], minutes: 30 }, 'root-ssh': { grant: 'never' } } }));
  const g = api(house('h-20', 'mark'), ['request', 'mark-discord', '--why', 'bridge', '--minutes', '999']);
  assert.match(g.body.stdout, /granted/);
  assert.equal(api(house('h-20', 'mark'), ['get', 'mark-discord']).body.stdout, 'DISCORD');
  const st = JSON.parse(api(house('h-20', 'mark'), ['status']).body.stdout);
  assert.equal(st[0].minutes, 30);
  // auto is for the agents it names: art asks instead.
  assert.match(api(house('h-21', 'art'), ['request', 'mark-discord', '--why', 'curious']).body.stdout, /asked the owner/);
  // A grant is the whole caller's: the same house id under another agent, or another service, has nothing.
  assert.equal(api(house('h-20', 'art'), ['get', 'mark-discord']).status, 403);
  assert.equal(api({ ...house('h-20', 'mark'), service: 'discord' }, ['get', 'mark-discord']).status, 403);
  // And the policy is read again at every get: moved to never, a live grant stops working at once.
  writeFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), JSON.stringify({ v: 1, default: 'ask', secrets: {
    'mark-discord': { grant: 'never' }, 'root-ssh': { grant: 'never' } } }));
  assert.equal(api(house('h-20', 'mark'), ['get', 'mark-discord']).status, 403);
  const no = api(house('h-20', 'mark'), ['request', 'root-ssh', '--why', 'please']);
  assert.equal(no.body.exit, 1);
  assert.match(no.body.stdout, /denied/);
  assert.equal(api(house('h-20', 'mark'), ['get', 'root-ssh']).status, 403);
});

test('requests: Always allow grants this one and every later house of that agent, until the owner stops it', { skip }, () => {
  cli(['add', 'onterris-always'], { input: 'ONTERRIS' });
  writeFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), JSON.stringify({ v: 1, default: 'ask', secrets: {
    'onterris-always': { grant: 'ask', minutes: 60 }, 'root-ssh': { grant: 'never' } } }));
  api(house('h-30'), ['request', 'onterris-always', '--why', 'pond work']);
  const ask = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('onterris-always'));
  assert.deepEqual(ask.actions.map((a) => a.action), ['grant', 'always', 'deny']);
  const always = ask.actions.find((a) => a.action === 'always');
  assert.equal(always.label, 'Always allow Art');
  assert.ok(always.confirm, 'a standing grant asks to be sure');
  const act = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'always', fields: always.fields }) }).stdout);
  assert.equal(act.ok, true, act.message);
  assert.equal(act.message, "Allowed: Art's onterris-always, and Art's houses get it without asking from now on.");
  // This house has it, and for a house's working day.
  assert.equal(api(house('h-30'), ['get', 'onterris-always']).body.stdout, 'ONTERRIS');
  assert.equal(JSON.parse(api(house('h-30'), ['status']).body.stdout)[0].minutes, 480);
  // The next house of art gets it without a card; mark still asks; never stays never.
  assert.match(api(house('h-31'), ['request', 'onterris-always', '--why', 'more pond']).body.stdout, /granted/);
  assert.match(api(house('h-32', 'mark'), ['request', 'onterris-always', '--why', 'x']).body.stdout, /asked the owner/);
  const pol = JSON.parse(readFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), 'utf-8'));
  assert.deepEqual(pol.secrets['onterris-always'], { grant: 'auto', agents: ['art'], minutes: 480 });
  assert.deepEqual(pol.secrets['root-ssh'], { grant: 'never' });
  const hist = JSON.parse(cli(['ui', '--json']).stdout).answered.find((a) => a.text.includes('pond work'));
  assert.match(hist.outcome, /from now on without asking/);
  // The secret's page says who has it without asking, and the owner can stop it there.
  const page = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'secret', query: { name: 'onterris-always' } }) }).stdout);
  const who = page.sections.find((s) => s.id === 'who').blocks[0].rows;
  const row = who.find((r) => r.agent === 'art' && r.label === 'When a house asks');
  assert.equal(row.value, "Art's houses get it without asking you, 8 hours at a time");
  assert.deepEqual(row.toggle, { action: 'auto', on: true, fields: { name: 'onterris-always', agent: 'art' } }, 'the agent id itself is unchanged');
  assert.deepEqual(who.find((r) => r.agent === 'art' && r.label === 'When a house starts').toggle.on, false);
  // The switch turned off: the panel posts its action with on = "".
  const stop = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'auto', fields: { ...row.toggle.fields, on: '' } }) }).stdout);
  assert.equal(stop.ok, true, stop.message);
  assert.equal(stop.message, "Art's houses will ask for onterris-always again.");
  assert.match(api(house('h-33'), ['request', 'onterris-always', '--why', 'again']).body.stdout, /asked the owner/);
  assert.deepEqual(JSON.parse(readFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), 'utf-8')).secrets['onterris-always'],
    { grant: 'ask', minutes: 480 }, 'Stop leaves the length as Always set it');
  // Art's Secrets tab says what it gets, each a row to the secret's page (its switches); mark's says nothing of art's.
  const tab = (agent) => JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }), extraEnv: { LOOM_SCOPE: agent } }).stdout);
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'always', fields: (api(house('h-39'), ['request', 'onterris-always', '--why', 'x']),
    JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('onterris-always')).actions[1].fields) }) });
  assert.deepEqual(tab('art').sections.find((s) => s.id === 'gets').blocks[0].rows.map((r) => [r.label, r.value, r.page]),
    [['onterris-always', 'When a house asks, without you', 'secret?name=onterris-always']]);
  assert.match(tab('art').intro, /^What Art's houses get/);
  // On an agent's tab, the secret's page holds only that agent's switches, and its value row leads to the household's page.
  const scoped = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'secret', query: { name: 'onterris-always' } }), extraEnv: { LOOM_SCOPE: 'art' } }).stdout);
  assert.deepEqual([...new Set(scoped.sections.find((s) => s.id === 'who').blocks[0].rows.map((r) => r.agent))], ['art']);
  assert.equal(scoped.sections.find((s) => s.id === 'secret').blocks[0].rows[0].page, 'household:secret?name=onterris-always');
  assert.equal(scoped.sections.find((s) => s.id === 'more'), undefined, 'no Remove on an agent\'s tab');
  // Mark's tab can't flip art's switches; art's can.
  for (const action of ['auto', 'houses']) {
    assert.equal(JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action, fields: { name: 'onterris-always', agent: 'art', on: '' } }),
      extraEnv: { LOOM_SCOPE: 'mark' } }).stdout).ok, false, `mark's tab can't flip art's ${action}`);
  }
  assert.equal(tab('mark').sections.find((s) => s.id === 'gets').blocks[0].text, "Nothing: Mark's houses ask you for every secret they don't start with.");
  assert.equal(tab('mark').sections.find((s) => s.id === 'gets').blocks[0].type, 'text');
  assert.equal(JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'stop-always', fields: { name: 'onterris-always', agent: 'art' } }),
    extraEnv: { LOOM_SCOPE: 'mark' } }).stdout).ok, false, "mark's tab can't stop art's");
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'stop-always', fields: { name: 'onterris-always', agent: 'art' } }) });
  // A live grant isn't pulled by stopping the standing one (Revoke does that), and a bad agent or name is refused.
  assert.equal(api(house('h-31'), ['get', 'onterris-always']).body.stdout, 'ONTERRIS');
  for (const fields of [{ name: 'onterris-always', agent: 'Art!' }, { name: 'nope', agent: 'art' }, { name: 'onterris-always', agent: 'art' }]) {
    assert.equal(JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'stop-always', fields }) }).stdout).ok, false);
  }
  // A secret moved to never while its card waited can't be always-allowed from it.
  api(house('h-34'), ['request', 'onterris-always', '--why', 'late']);
  const late = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.meta.includes('late')).actions.find((a) => a.action === 'always');
  const pol2 = JSON.parse(readFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), 'utf-8'));
  pol2.secrets['onterris-always'] = { grant: 'never' };
  writeFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), JSON.stringify(pol2));
  const refused = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'always', fields: late.fields }) }).stdout);
  assert.equal(refused.ok, false);
  assert.deepEqual(JSON.parse(readFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), 'utf-8')).secrets['onterris-always'], { grant: 'never' });
  // Removing a secret takes its standing grants with it: the name added again starts by asking.
  cli(['add', 'gone-later'], { input: 'G' });
  api(house('h-40'), ['request', 'gone-later', '--why', 'x']);
  const g = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('gone-later')).actions.find((a) => a.action === 'always');
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'always', fields: g.fields }) });
  assert.match(api(house('h-41'), ['request', 'gone-later', '--why', 'y']).body.stdout, /granted/);
  assert.equal(cli(['rm', 'gone-later']).status, 0);
  cli(['add', 'gone-later'], { input: 'G2' });
  assert.match(api(house('h-42'), ['request', 'gone-later', '--why', 'z']).body.stdout, /asked the owner/);
  const audit = readFileSync(join(env.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l).event)
    .filter((e) => !STORE_EVENTS.includes(e));
  assert.ok(audit.includes('always') && audit.includes('stop-always'), audit.join(' '));
});

test('requests: the owner\'s yes outlives the house that asked, once; the clock reads a request\'s state by id', { skip }, () => {
  cli(['add', 'carry-me'], { input: 'CARRIED' });
  const q = api(house('h-50'), ['request', 'carry-me', '--why', 'pond work']);
  const id = q.body.stdout.match(/q-[0-9a-f]{8}/)[0];
  assert.equal(cli(['state', id]).stdout, 'pending\n');
  const card = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('carry-me'));
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'grant', fields: card.actions[0].fields }) });
  assert.equal(cli(['state', id]).stdout, 'granted\n');
  // h-50 is gone; art's next house asks and gets it at once, without a second card.
  const next = api(house('h-51'), ['request', 'carry-me', '--why', 'resuming']);
  assert.match(next.body.stdout, /granted/);
  assert.equal(api(house('h-51'), ['get', 'carry-me']).body.stdout, 'CARRIED');
  // It moved: the house that asked (were it still up) reads it no more.
  assert.equal(api(house('h-50'), ['get', 'carry-me']).status, 403);
  assert.equal(JSON.parse(cli(['ui', '--json']).stdout).asks.filter((a) => a.text.includes('carry-me')).length, 0);
  // Once: a third house asks the owner again; another agent, or the agent's service, never carries it.
  assert.match(api(house('h-52'), ['request', 'carry-me', '--why', 'again']).body.stdout, /asked the owner/);
  assert.match(api(house('h-53', 'mark'), ['request', 'carry-me', '--why', 'x']).body.stdout, /asked the owner/);
  assert.match(api({ ...house('h-54'), service: 'discord' }, ['request', 'carry-me', '--why', 'x']).body.stdout, /asked the owner/);
  // A refusal doesn't carry.
  cli(['add', 'no-carry'], { input: 'N' });
  api(house('h-60'), ['request', 'no-carry', '--why', 'x']);
  const nc = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('no-carry'));
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'deny', fields: nc.actions.find((a) => a.action === 'deny').fields }) });
  assert.match(api(house('h-61'), ['request', 'no-carry', '--why', 'y']).body.stdout, /asked the owner/);
  // Revoking the original ends the carried one too.
  const live1 = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }), extraEnv: { LOOM_SCOPE: 'art' } }).stdout)
    .sections.find((s) => s.id === 'grants').blocks[0].rows.find((r) => r.label.includes('carry-me') && r.act && r.detail === '\u201cpond work\u201d');
  if (live1) {
    cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'revoke', fields: live1.act.fields }) });
    assert.equal(api(house('h-51'), ['get', 'carry-me']).status, 403);
  } else {
    assert.fail('the original grant is still listed as live, with Revoke');
  }
  // state: a bad or unknown id is refused, and houses can't call it through the API.
  assert.equal(cli(['state', 'nope']).status, 2);
  assert.equal(cli(['state', 'q-00000000']).status, 3);
  assert.notEqual(api(house('h-51'), ['state', id]).body.exit, 0);
});

test('requests: an answer records who gave it (the caller loom names), and the history says so', { skip }, () => {
  cli(['add', 'who-said'], { input: 'W' });
  api(house('h-70'), ['request', 'who-said', '--why', 'x']);
  const ask = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('who-said'));
  const act = JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'grant', fields: ask.actions[0].fields,
    caller: { kind: 'owner', who: 'jonathan-barket', agents: '*' } }) }).stdout);
  assert.equal(act.ok, true, act.message);
  const hist = JSON.parse(cli(['ui', '--json']).stdout).answered.find((a) => a.text.includes('who-said'));
  assert.match(hist.outcome, /^Allowed for \d+ min by jonathan-barket\.$/);
  const audit = readFileSync(join(env.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l)).filter((e) => e.secret === 'who-said' && e.event === 'grant');
  assert.equal(audit[0].who, 'jonathan-barket');
  // A caller that isn't an owner, or a who that isn't a slug, records nobody.
  api(house('h-71', 'mark'), ['request', 'who-said', '--why', 'y']);  // another agent: the carry is art's
  const ask2 = JSON.parse(cli(['ui', '--json']).stdout).asks.find((a) => a.text.includes('who-said'));
  cli(['ui', 'act', '--json'], { input: JSON.stringify({ action: 'deny', fields: ask2.actions.find((a) => a.action === 'deny').fields, caller: { kind: 'owner', who: 'Not A Slug' } }) });
  const denied = JSON.parse(cli(['ui', '--json']).stdout).answered.find((a) => a.outcome.startsWith('Denied'));
  assert.equal(denied.outcome, 'Denied.');
});

test('requests: a grant row says its state in words and its time in the box\'s 12-hour local time, with the date if not today', { skip }, () => {
  cli(['add', 'when-ends'], { input: 'W' });
  for (const h of ['h-80', 'h-81', 'h-82', 'h-83']) api(house(h), ['request', 'when-ends', '--why', `ask from ${h}`]);
  const file = join(env.LOOM_SECRETS_DIR, 'requests.json');
  const d = JSON.parse(readFileSync(file, 'utf-8'));
  const of = (h) => Object.values(d.requests).find((r) => r.secret === 'when-ends' && r.house === h);
  const later = new Date(Date.now() + 3 * 86_400_000);
  later.setHours(15, 5, 0, 0);
  const nextYear = new Date(later.getFullYear() + 1, 0, 2, 9, 7);
  Object.assign(of('h-80'), { state: 'granted', by: 'owner', decided: of('h-80').at, expires: later.toISOString() });
  Object.assign(of('h-81'), { state: 'granted', by: 'owner', decided: of('h-81').at, expires: nextYear.toISOString() });
  Object.assign(of('h-82'), { state: 'granted', by: 'owner', decided: of('h-82').at, expires: new Date(Date.now() - 60_000).toISOString() });
  writeFileSync(file, JSON.stringify(d));
  const tab = JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: '' }), extraEnv: { LOOM_SCOPE: 'art' } }).stdout);
  const sec = (id) => tab.sections.find((s) => s.id === id);
  const live = (h) => sec('grants').blocks[0].rows.find((r) => r.detail === `\u201cask from ${h}\u201d`);
  const month = later.toLocaleDateString('en-US', { month: 'short' });
  assert.equal(live('h-80').value, `Can read it until ${month} ${later.getDate()}, 3:05 PM`);
  assert.equal(live('h-81').value, `Can read it until Jan 2, ${nextYear.getFullYear()}, 9:07 AM`);
  // Waiting: a row whose sheet holds the three answers; the past: a wrapped list, each reason whole.
  const waiting = sec('waiting').blocks[0].rows.find((r) => r.value === '\u201cask from h-83\u201d');
  assert.equal(waiting.label, 'Art asks for when-ends');
  assert.match(waiting.detail, /^For \d+ min \u00b7 asked just now$/);
  assert.deepEqual(waiting.sheet.blocks.find((b) => b.type === 'buttons').items.map((i) => i.action), ['grant', 'always', 'deny']);
  const past = sec('requests').blocks[0];
  assert.equal(past.wrap, true);
  assert.equal(past.items.find((i) => i.meta.endsWith('\u201cask from h-82\u201d')).meta, 'Expired \u00b7 just now \u00b7 \u201cask from h-82\u201d');
  for (const r of sec('grants').blocks[0].rows) assert.doesNotMatch(`${r.label} ${r.value}`, /UTC|\d{4}-\d{2}-\d{2}|h-\d/);
});

// agent-runtime.md, section 6, Secrets: the runtime says where a secret lands in a house; the policy here decides
// whether an agent may have it (`may`), and the runtime reads it for a house it's starting (`issue`), with no
// environment flag that unlocks reading.
test('may: allowed for an agent its houses list, denied by never, else ask; never a value', { skip }, () => {
  cli(['init']);
  cli(['add', 'house-token'], { input: 'hv-1' });
  assert.equal(cli(['may', 'art', 'house-token']).stdout.trim().split(':')[0], 'ask');
  assert.equal(cli(['may', 'art', 'house-token']).status, 1);
  assert.equal(cli(['policy', 'houses', 'house-token', 'art']).status, 0);
  const yes = cli(['may', 'art', 'house-token', '--json']);
  assert.equal(yes.status, 0);
  assert.deepEqual(JSON.parse(yes.stdout), { may: 'allowed' });
  assert.equal(JSON.parse(cli(['may', 'mark', 'house-token', '--json']).stdout).may, 'ask');
  assert.doesNotMatch(yes.stdout + yes.stderr, /hv-1/);
});

test('issue: only the runtime\'s own process, only when may says allowed; LOOM_SECRETS_ALLOW_GET unlocks nothing', { skip }, () => {
  cli(['init']);
  cli(['add', 'issue-me'], { input: 'iv-1' });
  cli(['policy', 'houses', 'issue-me', 'art']);
  const rt = { LOOM_PIECE_NAME: 'runtime' };
  const ok = cli(['issue', 'issue-me', '--agent', 'art', '--house', 'h-9'], { extraEnv: rt });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout, 'iv-1');
  // Not the runtime: refused, whatever the flag says.
  const body = cli(['issue', 'issue-me', '--agent', 'art'], { extraEnv: { LOOM_SECRETS_ALLOW_GET: '1' } });
  assert.equal(body.status, 4);
  assert.equal(body.stdout, '');
  // Another agent, or a secret the policy doesn't give its houses: refused.
  assert.equal(cli(['issue', 'issue-me', '--agent', 'mark'], { extraEnv: rt }).status, 4);
  cli(['policy', 'houses', 'issue-me', 'art', '--off']);
  assert.equal(cli(['issue', 'issue-me', '--agent', 'art'], { extraEnv: rt }).status, 4);
  // The record says it was issued, never the value.
  const log = readFileSync(join(env.LOOM_SECRETS_DIR, 'audit.jsonl'), 'utf-8');
  assert.match(log, /"event":"issue","secret":"issue-me","agent":"art","house":"h-9","by":"runtime"/);
  assert.doesNotMatch(log, /iv-1/);
});

test('policy houses-import takes the runtime\'s old map; the policy is never another piece\'s or a house\'s to change', { skip }, () => {
  cli(['init']);
  assert.equal(cli(['policy', 'houses-import'], { input: JSON.stringify({ art: ['a-tok', 'b-tok'], mark: ['a-tok'] }) }).status, 0);
  assert.equal(JSON.parse(cli(['may', 'mark', 'a-tok', '--json']).stdout).may, 'allowed');
  assert.equal(JSON.parse(cli(['may', 'mark', 'b-tok', '--json']).stdout).may, 'ask');
  assert.equal(cli(['policy', 'houses', 'a-tok', 'mark'], { extraEnv: { LOOM_PIECE_NAME: 'runtime' } }).status, 4);
  assert.equal(cli(['policy', 'houses', 'a-tok', 'mark'], { extraEnv: { HOUSE_ID: 'h-1' } }).status, 4);
});

test('the secret page\'s switches: houses (at start) and auto (when asked) apply at once; the store says who gets it and when last used', { skip }, () => {
  cli(['add', 'switch-me'], { input: 'S' });
  const act = (action, fields) => JSON.parse(cli(['ui', 'act', '--json'], { input: JSON.stringify({ action, fields }) }).stdout);
  const on = act('houses', { name: 'switch-me', agent: 'mark', on: 'on' });
  assert.deepEqual(on, { ok: true, page: '', message: "Mark's houses get switch-me when they start." });
  assert.equal(cli(['may', 'mark', 'switch-me']).status, 0, 'may says allowed once the switch is on');
  assert.equal(act('auto', { name: 'switch-me', agent: 'mark', on: 'on' }).ok, true);
  const rule = JSON.parse(readFileSync(join(env.LOOM_SECRETS_DIR, 'policy.json'), 'utf-8')).secrets['switch-me'];
  assert.deepEqual(rule, { grant: 'auto', agents: ['mark'], minutes: 480, houses: ['mark'] });
  const page = () => JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'list', query: { of: 'all' } }) }).stdout);
  const row = () => page().sections.find((s) => s.id === 'store').blocks.find((b) => b.type === 'panel').rows.find((r) => r.label === 'switch-me');
  assert.equal(row().value, 'Mark at start and when asked');
  assert.equal(row().detail, 'Not given to a house yet');
  // The runtime hands it to a house it starts: the store row says so, in words.
  assert.equal(cli(['issue', 'switch-me', '--agent', 'mark', '--house', 'h-90'], { extraEnv: { LOOM_PIECE_NAME: 'runtime' } }).status, 0);
  assert.equal(row().detail, "Last given to Mark's house just now");
  // The filter: at start finds it, never doesn't.
  const filtered = (who) => JSON.parse(cli(['ui', 'page', '--json'], { input: JSON.stringify({ path: 'list', query: { of: 'all', who } }) }).stdout)
    .sections.find((s) => s.id === 'store').blocks.flatMap((b) => b.rows ?? []).map((r) => r.label);
  assert.ok(filtered('start').includes('switch-me'));
  assert.ok(!filtered('never').includes('switch-me'));
  // Off again, both; a bad agent or a missing secret is refused.
  assert.equal(act('houses', { name: 'switch-me', agent: 'mark', on: '' }).message, "Mark's houses start without switch-me.");
  assert.equal(act('auto', { name: 'switch-me', agent: 'mark', on: '' }).message, "Mark's houses will ask for switch-me again.");
  assert.equal(row().value, 'Asks you first');
  assert.equal(act('houses', { name: 'switch-me', agent: 'Mark!', on: 'on' }).ok, false);
  assert.equal(act('auto', { name: 'not-stored', agent: 'mark', on: 'on' }).ok, false);
});

// ---- the summary: 61 secrets, a short index, groups a tap away, no value anywhere -----------------------

test('61 secrets: the index is a short summary (needs a look first, then a row a group), each group links through, no value anywhere', { skip }, () => {
  const d = join(dir, 'ui-61');
  const extra = { LOOM_SECRETS_DIR: d, LOOM_SECRETS_SOPS: SOPS };
  const run61 = (args, input) => spawnSync(process.execPath, [CLI, ...args], { input: input ?? '', env: { ...env, ...extra }, encoding: 'utf-8' });
  assert.equal(run61(['init']).status, 0);
  // 61 real secrets with real values, encrypted in one sops call (the way encrypt() does it).
  const values = {};
  for (let i = 0; i < 61; i++) values[`s${String(i).padStart(2, '0')}-token`] = `VALUE-${i}-${'q'.repeat(i % 7)}-zx81`;
  const recipient = execFileSync(KEYGEN, ['-y', join(d, 'age.key')], { encoding: 'utf-8' }).trim();
  const enc = spawnSync('sh', ['-c', 'cat | "$0" "$@"', SOPS, '--encrypt', '--age', recipient, '--input-type', 'json', '--output-type', 'json',
    '--filename-override', 'store.sops.json', '/dev/stdin'], { input: JSON.stringify(values), encoding: 'utf-8' });
  assert.equal(enc.status, 0, enc.stderr);
  writeFileSync(join(d, 'store.sops.json'), enc.stdout, { mode: 0o600 });
  // Art's houses get 9 at start, Mark's 3 (one shared with Art) and 1 without asking; 2 are never given out;
  // ghost-token is given to Art's houses but isn't stored.
  const secrets = {};
  for (let i = 0; i < 9; i++) secrets[`s${String(i).padStart(2, '0')}-token`] = { houses: ['art'] };
  secrets['s08-token'] = { houses: ['art', 'mark'] };
  secrets['s09-token'] = { houses: ['mark'] };
  secrets['s10-token'] = { houses: ['mark'], grant: 'auto', agents: ['mark'], minutes: 480 };
  secrets['s11-token'] = { grant: 'auto', agents: ['mark'], minutes: 480 };
  secrets['s59-token'] = { grant: 'never' };
  secrets['s60-token'] = { grant: 'never' };
  secrets['ghost-token'] = { houses: ['art'] };
  writeFileSync(join(d, 'policy.json'), JSON.stringify({ v: 1, default: 'ask', secrets }));
  // The record: houses were given some; loom's machine read one; one was set two years ago.
  const old = new Date(Date.now() - 2 * 365 * 86_400_000).toISOString();
  writeFileSync(join(d, 'audit.jsonl'), [
    { at: new Date().toISOString(), event: 'issue', secret: 's00-token', agent: 'art', house: 'h-1', by: 'runtime' },
    { at: new Date().toISOString(), event: 'read', id: 'q-00000001', secret: 's20-token', agent: 'art', house: 'h-1' },
    { at: old, event: 'set', secret: 's30-token', how: 'add' },
  ].map((e) => JSON.stringify(e)).join('\n') + '\n');
  // loom's machine reads one (a host script): on record from now on, never its value in the record.
  assert.equal(run61(['get', 's21-token', '--reveal'], '').status, 4, 'still gated');
  assert.equal(spawnSync(process.execPath, [CLI, 'get', 's21-token', '--reveal'], { env: { ...env, ...extra, LOOM_SECRETS_ALLOW_GET: '1' }, encoding: 'utf-8' }).stdout, values['s21-token']);

  const pg = (path, query = {}) => ui(['page'], { path, query }, extra);
  const seen = [];
  const json = (p) => { const s = JSON.stringify(p); seen.push(s); return s; };

  const index = pg('');
  json(index);
  // Short: a handful of sections and rows, no secret's own row, and well under a phone's few screens.
  assert.deepEqual(index.sections.map((s) => s.id), ['look', 'groups', 'add', 'policy']);
  const rows = index.sections.flatMap((s) => s.blocks).flatMap((b) => b.rows ?? []);
  assert.ok(rows.length <= 14, `${rows.length} rows on the index`);
  for (const name of Object.keys(values)) assert.ok(!rows.some((r) => r.label === name), `${name} has its own row on the index`);
  // Needs a look first: the missing one (with an add form for that name), then the old, then the unused.
  const look = rowsOf(index, 'look');
  assert.deepEqual(look.map((r) => r.label), ['ghost-token', 'Not changed in a year', 'Not used by anyone']);
  assert.equal(look[0].tone, 'bad');
  assert.deepEqual(look[0].edit.hidden, { name: 'ghost-token' });
  assert.deepEqual(look[0].edit.fields.map((f) => [f.name, f.kind, 'value' in f]), [['value', 'secret', false]]);
  assert.equal(look[1].value, '1 secret');
  // Groups: a row each with its count, by who can use them.
  const groups = rowsOf(index, 'groups');
  assert.deepEqual(groups.map((r) => [r.label, r.value]), [
    ['Art', '9 secrets'], ['Mark', '4 secrets'], ["Loom's machine", '1 secret'], ['Only when you say yes', '47 secrets'],
    ['Never given out', '2 secrets'], ['All secrets', '61'],
  ]);
  // Each group links through to a list of exactly its secrets, each a tap to its own page.
  const want = { Art: 9, Mark: 4, "Loom's machine": 1, 'Only when you say yes': 47, 'Never given out': 2, 'All secrets': 61 };
  const everyName = new Set();
  for (const g of groups) {
    const [path, qs] = g.page.split('?');
    assert.equal(path, 'list');
    const list = pg('list', Object.fromEntries(new URLSearchParams(qs)));
    json(list);
    const listed = rowsOf(list, 'store');
    assert.equal(listed.length, want[g.label], g.label);
    for (const r of listed) { assert.equal(r.page, `secret?name=${encodeURIComponent(r.label)}`); everyName.add(r.label); }
  }
  assert.equal(everyName.size, 61);
  assert.ok(storeNames(pg('list', { of: 'agent:mark' })).includes('s08-token'), 'shared secrets are in both agents');
  // The needs-a-look lists link through too.
  for (const r of look.filter((x) => x.page)) json(pg('list', Object.fromEntries(new URLSearchParams(r.page.split('?')[1]))));
  assert.deepEqual(storeNames(pg('list', { of: 'old' })), ['s30-token']);
  const unused = storeNames(pg('list', { of: 'unused' }));
  assert.equal(unused.length, 45, 'ask-only, minus s20 (a house read it) and s21 (loom read it)');
  assert.ok(!unused.includes('s20-token') && !unused.includes('s21-token'));
  assert.deepEqual(rowsOf(pg('list', { of: 'missing' }), 'store').map((r) => r.label), ['ghost-token']);
  assert.deepEqual(pg('list', { of: 'nobody' }), { title: 'Not found', sections: [] });
  // Each secret's own page: where it's used, who can read it, when it was set, and its actions.
  for (const name of Object.keys(values)) json(pg('secret', { name }));
  const s21 = pg('secret', { name: 's21-token' });
  const where = rowsOf(s21, 'secret').find((r) => r.label === 'Where it’s used');
  assert.match(where.value, /^Loom's machine, just now$/);
  assert.match(rowsOf(pg('secret', { name: 's30-token' }), 'secret').find((r) => r.label === 'Set').value, /^Added on [A-Z][a-z]{2} \d{1,2}, \d{4}$/);
  assert.equal(rowsOf(pg('secret', { name: 's31-token' }), 'secret').find((r) => r.label === 'Set').value, 'Not on record');
  const s00 = pg('secret', { name: 's00-token' });
  assert.equal(s00.sections.find((s) => s.id === 'who').title, 'Who can read it');
  assert.deepEqual(rowsOf(s00, 'more').map((r) => r.label), ['The record', 'Remove']);
  assert.equal(rowsOf(s00, 'secret')[0].edit.action, 'replace');
  // No value anywhere in any page, nor in the record.
  const everything = seen.join('\n');
  for (const v of Object.values(values)) assert.ok(!everything.includes(v), `a value reached the page: ${v.slice(0, 8)}...`);
  const record = readFileSync(join(d, 'audit.jsonl'), 'utf-8');
  assert.match(record, /"event":"host-read","secret":"s21-token","how":"get"/);
  for (const v of Object.values(values)) assert.ok(!record.includes(v), 'a value reached the record');
});

test('a house that was meant to start with a secret that isn\'t stored shows under Needs a look; adding it clears it', { skip }, () => {
  const d = join(dir, 'ui-missing');
  const extra = { LOOM_SECRETS_DIR: d, LOOM_SECRETS_SOPS: SOPS };
  const run = (args, input, more = {}) => spawnSync(process.execPath, [CLI, ...args], { input: input ?? '', env: { ...env, ...extra, ...more }, encoding: 'utf-8' });
  assert.equal(run(['init']).status, 0);
  assert.equal(run(['add', 'gone-token'], 'v-gone').status, 0);
  assert.equal(run(['policy', 'houses', 'gone-token', 'art']).status, 0);
  assert.equal(run(['rm', 'gone-token']).status, 0);
  // The rule stays; the runtime tries to hand it to a house it starts, and can't.
  assert.equal(run(['issue', 'gone-token', '--agent', 'art', '--house', 'h-5'], '', { LOOM_PIECE_NAME: 'runtime' }).status, 3);
  const look = () => rowsOf(ui(['page'], { path: '', query: {} }, extra), 'look');
  assert.deepEqual(look().map((r) => [r.label, r.value]), [['gone-token', 'Not in the store']]);
  assert.match(look()[0].detail, /The rules give it to Art's houses/);
  // Its add form stores it (hidden name, value from stdin JSON), and it leaves the list.
  const r = ui(['act'], { action: 'add', path: '', fields: { ...look()[0].edit.hidden, value: 'v-back' } }, extra);
  assert.equal(r.ok, true, r.message);
  assert.ok(!look().some((x) => x.label === 'gone-token'));
  assert.equal(rowsOf(ui(['page'], { path: 'secret', query: { name: 'gone-token' } }, extra), 'secret').find((x) => x.label === 'Set').value, 'Added just now');
});
