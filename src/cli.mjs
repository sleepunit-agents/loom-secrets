#!/usr/bin/env node
// loom-secrets: loom's `secrets` piece (loom docs/extensions.md). An encrypted
// store of named secrets, sops + age underneath. `loom secrets add google-pass`
// reaches it through loom's piece dispatch, or run it directly.
//
// The rules it keeps (CONTRACT.md):
//   - a value never travels in argv: it comes from stdin or a no-echo prompt
//   - the store on disk is sops-encrypted; names are readable, values aren't
//   - `list` never decrypts; nothing prints a value unless `get --reveal` is
//     allowed (an interactive terminal, or LOOM_SECRETS_ALLOW_GET=1 set by the
//     host side, e.g. the selvedge); a body is refused by default
//   - `podman` injects a value into a podman secret without printing it,
//     behind the same gate as `get --reveal`
//   - the gate is a guardrail, not a boundary: a same-user process that can
//     read the age key can run sops itself. The boundary is where the key
//     lives (README, "Threat model").
//   - loom's page (`ui`) is write-only: add, replace, remove. A value comes in
//     on `ui act`'s stdin JSON and never goes out in any ui answer
//   - it never touches loom's stores
//   - `bundle export` / `bundle import` are loom's bundle seam: export hands over the
//     decrypted map re-encrypted (age) to the owner's recipients, import opens
//     it with the owner's identity and re-encrypts it to this machine's key.
//     Plaintext only ever travels on stdin/stdout pipes, never argv or disk
import { spawnSync } from 'node:child_process';
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { all as allRequests, answer, mayRead, mine, readPolicy, request, RequestError, standing, stopAlways, forgetStanding } from './requests.mjs';

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const STORE = 'store.sops.json';
const KEY = 'age.key';

const USAGE = `Usage: loom secrets <command> [args]

  init                          Create the age key and an empty store
  add <name> [--force]          Store a value read from stdin (or a no-echo prompt)
  list [--json]                 Names only (never decrypts)
  rm <name>                     Delete a secret
  get <name> --reveal           Print a value: only at a terminal, or with
                                LOOM_SECRETS_ALLOW_GET=1 set by the host side
  podman <name> <podman-name>   Put the value into a podman secret, unprinted
  ui --json                     loom's page: the manifest (tab, Home tile)
  ui page --json                loom's page: one page, from {path, query} on stdin
  ui act --json                 loom's page: add / replace / remove, from
                                {action, path, fields} on stdin. Write-only:
                                there is no action that reads a value back
  api --json                    loom's piece API, {caller, path:'run', body:{argv}} on stdin, for
                                a house's own token only (agent:<a>@<house>):
                                  request <name> --why TEXT [--minutes N]
                                  get <name>    (with a live grant for this house)
                                  status        (this house's requests)
  bundle export                 loom's bundle: the store, age-encrypted to
                                $LOOM_EXPORT_RECIPIENTS (comma-separated), on stdout
  bundle import [--force]       loom's restore: a part from export on stdin,
                                opened with $LOOM_IMPORT_IDENTITY and re-encrypted
                                to this machine's key (refuses a non-empty store
                                without --force)

Values are never taken from argv. Store: $LOOM_SECRETS_DIR (default
~/.config/loom-secrets), sops + age. Binaries: $LOOM_SECRETS_SOPS (default
sops), $LOOM_SECRETS_AGE (default age), $LOOM_SECRETS_AGE_KEYGEN (default
age-keygen), $LOOM_SECRETS_PODMAN (default podman).
`;

class Fail extends Error {
  constructor(message, code = 1) { super(message); this.code = code; }
}

function config(env) {
  const dir = env.LOOM_SECRETS_DIR || join(env.HOME || homedir(), '.config', 'loom-secrets');
  return {
    dir,
    store: join(dir, STORE),
    key: env.SOPS_AGE_KEY_FILE || join(dir, KEY),
    sops: env.LOOM_SECRETS_SOPS || 'sops',
    age: env.LOOM_SECRETS_AGE || 'age',
    keygen: env.LOOM_SECRETS_AGE_KEYGEN || 'age-keygen',
    podman: env.LOOM_SECRETS_PODMAN || 'podman',
  };
}

function checkName(name) {
  if (!name) throw new Fail('a secret name is required', 2);
  if (!NAME.test(name)) throw new Fail(`not a secret name: ${JSON.stringify(name)} (letters, digits, . _ -; 64 max)`, 2);
}

function run(cmd, args, { input, env } = {}) {
  const r = spawnSync(cmd, args, { input, env, encoding: 'utf-8', maxBuffer: 16 * 1024 * 1024 });
  if (r.error) throw new Fail(`can't run ${cmd}: ${r.error.message}`);
  if (r.status !== 0) throw new Fail(`${cmd} failed: ${(r.stderr || '').trim().split('\n').pop()}`);
  return r.stdout;
}

function recipient(c) {
  if (!existsSync(c.key)) throw new Fail(`no age key at ${c.key} (run: loom secrets init)`);
  return run(c.keygen, ['-y', c.key]).trim();
}

/** Names straight from the encrypted file: sops leaves keys readable. */
function names(c) {
  if (!existsSync(c.store)) return [];
  const doc = JSON.parse(readFileSync(c.store, 'utf-8'));
  return Object.keys(doc).filter((k) => k !== 'sops').sort();
}

function decrypt(c, env) {
  if (!existsSync(c.store)) return {};
  const out = run(c.sops, ['--decrypt', '--input-type', 'json', '--output-type', 'json', c.store],
    { env: { ...env, SOPS_AGE_KEY_FILE: c.key } });
  return JSON.parse(out);
}

function encrypt(c, env, data) {
  // The plaintext goes in on stdin, never argv or disk. sops reads it from
  // /dev/stdin, which must be a real pipe: node feeds spawn input through a
  // socketpair, and opening that as /dev/stdin fails (ENXIO). A shell pipe
  // in front fixes that; the shell's argv carries only fixed flags.
  const out = run('sh',
    ['-c', 'cat | "$0" "$@"', c.sops,
      '--encrypt', '--age', recipient(c), '--input-type', 'json', '--output-type', 'json',
      '--filename-override', STORE, '/dev/stdin'],
    { input: JSON.stringify(data), env });
  const tmp = `${c.store}.tmp-${process.pid}`;
  writeFileSync(tmp, out, { mode: 0o600 });
  renameSync(tmp, c.store);
}

/** One writer at a time: an O_EXCL lock file beside the store. */
function withLock(c, fn) {
  const lock = `${c.store}.lock`;
  let fd;
  try { fd = openSync(lock, 'wx', 0o600); }
  catch { throw new Fail(`store is locked (${lock}); another write is in progress, or a stale lock to remove`); }
  try { return fn(); }
  finally { closeSync(fd); rmSync(lock, { force: true }); }
}

/**
 * The one write path, shared by `add` and the page. `mode` is 'new' (refuse
 * an existing name), 'existing' (the name must be there) or 'any' (--force).
 * The value reaches sops on stdin only (encrypt), never argv, env or disk.
 */
function put(c, env, name, value, mode) {
  checkName(name);
  withLock(c, () => {
    const data = decrypt(c, env);
    if (mode === 'new' && Object.hasOwn(data, name)) throw new Fail(`${name} already exists (pass --force to replace it)`, 3);
    if (mode === 'existing' && !Object.hasOwn(data, name)) throw new Fail(`no secret named ${name}`, 3);
    data[name] = value;
    encrypt(c, env, data);
  });
}

function remove(c, env, name) {
  checkName(name);
  withLock(c, () => {
    const data = decrypt(c, env);
    if (!Object.hasOwn(data, name)) throw new Fail(`no secret named ${name}`, 3);
    delete data[name];
    encrypt(c, env, data);
  });
  forgetStanding(c, name);
}

async function readValue(io) {
  if (!io.stdinIsTTY) {
    const chunks = [];
    for await (const chunk of io.stdin) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks).toString('utf-8').replace(/\r?\n$/, '');
  }
  // A terminal: prompt with echo off.
  io.stderr('value: ');
  const stdin = io.stdin;
  stdin.setRawMode?.(true);
  return new Promise((resolve, reject) => {
    let value = '';
    const onData = (buf) => {
      for (const ch of buf.toString('utf-8')) {
        if (ch === '\r' || ch === '\n') { done(); return resolve(value); }
        if (ch === '\u0003') { done(); return reject(new Fail('cancelled', 130)); }
        if (ch === '\u007f') value = value.slice(0, -1);
        else value += ch;
      }
    };
    const done = () => { stdin.off('data', onData); stdin.setRawMode?.(false); stdin.pause(); io.stderr('\n'); };
    stdin.on('data', onData);
    stdin.resume();
  });
}

// ---- loom's page (contract v2) -------------------------------------------
// Everything below answers with data for loom to render; never markup, never
// a value. The only way in for a value is `ui act`'s stdin JSON.

const NAME_HINT = 'Letters, digits, dot, dash and underscore. It starts with a letter or digit, 64 at most. ' +
  'The name is the only part anyone sees again.';
const MAX_VALUE = 64 * 1024;          // bytes, as loom's own cap on a post
const MAX_REQUEST = 1024 * 1024;      // stdin JSON for page/act
const PER_PART = 200;                 // loom: 200 rows a list
const NOT_FOUND = { title: 'Not found', sections: [] };

/** stdin JSON for `ui page` / `ui act`. Anything unreadable comes back as null. */
async function readRequest(io) {
  const chunks = [];
  let size = 0;
  for await (const chunk of io.stdin) {
    size += chunk.length;
    if (size > MAX_REQUEST) return null;
    chunks.push(Buffer.from(chunk));
  }
  try {
    const req = JSON.parse(Buffer.concat(chunks).toString('utf-8'));
    return req && typeof req === 'object' && !Array.isArray(req) ? req : null;
  } catch { return null; }
}

function uiManifest(c) {
  const keyed = existsSync(c.key);
  return {
    v: 2,
    tab: { label: 'Secrets' },
    tile: {
      label: 'Secrets',
      value: String(names(c).length),
      detail: keyed ? 'Key on this host' : 'No key',
      tone: keyed ? 'ok' : 'bad',
      page: '',
    },
    // A house asking for a secret is the owner's call: a card with Allow and Deny (README, "Requests").
    asks: pendingAsks(c),
    // loom's Inbox, Answered: what was decided, by the owner or the policy.
    answered: answeredRequests(c),
  };
}

const OUTCOME = {
  granted: (r) => r.always ? `Allowed, and from now on without asking.` : `Allowed for ${r.minutes} min${r.by === 'owner' ? '' : ' (by the policy)'}.`,
  expired: (r) => `Allowed for ${r.minutes} min${r.by === 'owner' ? '' : ' (by the policy)'}; it ran out.`,
  denied: (r) => `Denied${r.by === 'owner' ? '' : ' (by the policy)'}.`,
  revoked: () => 'Allowed, then revoked.',
};

function answeredRequests(c) {
  return allRequests(c).filter((r) => OUTCOME[r.state]).slice(0, 20).map((r) => ({
    text: `${r.agent} asked for ${r.secret}: \u201c${r.why}\u201d`.slice(0, 300), outcome: OUTCOME[r.state](r),
    at: r.decided ?? r.at, kind: 'permission', agent: r.agent, page: '',
  }));
}

function pendingAsks(c) {
  return allRequests(c).filter((r) => r.state === 'pending').slice(0, 10).map((r) => ({
    text: `${r.agent} asks for ${r.secret}`,
    meta: `house ${r.house}, for ${r.minutes} min: \u201c${r.why}\u201d`,
    tone: 'warn', at: r.at, agent: r.agent, page: '', kind: 'permission',
    actions: [
      { action: 'grant', label: `Allow ${r.minutes} min`, tone: 'primary', fields: { id: r.id } },
      { action: 'always', label: `Always allow ${r.agent}`, fields: { id: r.id },
        confirm: `Every house of ${r.agent} gets ${r.secret} without asking, 8 h at a time, until you stop it on the secret's page.` },
      { action: 'deny', label: 'Deny', tone: 'danger', fields: { id: r.id } },
    ],
  }));
}

/** The page's Requests: what's waiting, what's live (each revocable), and what was decided. */
function requestSections(c) {
  const rs = allRequests(c);
  if (!rs.length) return [];
  const item = (r) => ({
    text: `${r.agent} · ${r.secret}`,
    meta: `${r.house} · ${r.state}${r.expires && r.state === 'granted' ? ` until ${r.expires.slice(11, 16)} UTC` : ''} · \u201c${r.why}\u201d`,
    tone: r.state === 'pending' ? 'warn' : r.state === 'granted' ? 'ok' : undefined,
    ...(r.state === 'granted' ? { act: { action: 'revoke', label: 'Revoke', tone: 'danger', fields: { id: r.id }, confirm: `${r.house} won't be able to read ${r.secret} again.` } } : {}),
  });
  return [{ id: 'requests', title: 'Requests', blocks: [{ type: 'list', items: rs.slice(0, 20).map(item) }] }];
}

/** Who gets what without asking (policy.json): auto and never, and what everything else does. */
function policySection(c) {
  const p = readPolicy(c);
  const rules = Object.entries(p.secrets).filter(([, r]) => r && (r.grant === 'auto' || r.grant === 'never'));
  const items = [
    { label: 'Anything else', value: p.default === 'ask' ? 'asks you' : p.default === 'auto' ? 'granted to any house' : 'refused' },
    ...rules.map(([name, r]) => ({ label: name, value: r.grant === 'never' ? 'never' : `auto for ${(r.agents || []).join(', ') || 'nobody'}, ${r.minutes || 60} min` })),
  ];
  return { id: 'policy', side: true, title: 'Who gets what', blocks: [{ type: 'kv', items }, { type: 'text', tone: 'muted', text: `policy.json in ${c.dir}` }] };
}

function uiPage(c, req) {
  if (!req || typeof req.path !== 'string') return NOT_FOUND;
  const query = req.query && typeof req.query === 'object' ? req.query : {};
  // A name rides in the query: loom's page paths are lowercase, and names needn't be.
  if (req.path === 'secret') return secretPage(c, String(query.name ?? ''));
  if (req.path !== '') return NOT_FOUND;
  const all = names(c);
  const keyed = existsSync(c.key);
  const parts = Math.max(1, Math.ceil(all.length / PER_PART));
  let part = /^[1-9][0-9]{0,5}$/.test(String(query.part ?? '')) ? Number(query.part) : 1;
  if (part > parts) part = 1;
  const shown = all.slice((part - 1) * PER_PART, part * PER_PART);

  // The board's order: what's stored (each a row: tap it to replace or remove it), then Add a secret.
  const sections = [];
  if (!keyed) sections.push({ id: 'key', blocks: [{ type: 'callout', tone: 'bad', title: 'No age key',
    text: `There is no age key at ${c.key}, so nothing can be stored. Run: loom secrets init` }] });
  sections.push(...requestSections(c));
  sections.push({ id: 'store', blocks: shown.length
    ? [{ type: 'list', items: shown.map((name) => ({ text: name, page: `secret?name=${encodeURIComponent(name)}` })) }]
    : [{ type: 'text', tone: 'muted', text: 'Nothing stored yet.' }] });
  sections.push({ id: 'add', title: 'Add a secret', blocks: [{
    type: 'form', action: 'add', submit: 'Save',
    note: 'The value goes straight to the secrets piece and into the encrypted store. It is never shown here again.',
    fields: [
      { name: 'name', label: 'Name', kind: 'text', hint: NAME_HINT, required: true },
      { name: 'value', label: 'Value', kind: 'secret', required: true,
        hint: 'One line, 64 KB at most. For a multi-line value (a JSON key, an .env), pipe it in: loom secrets add <name>' },
    ],
  }] });
  if (parts > 1) {
    const options = [];
    for (let p = 1; p <= parts; p++) {
      const from = (p - 1) * PER_PART;
      options.push({ value: p === 1 ? '' : String(p),
        label: `${all[from]} to ${all[Math.min(from + PER_PART, all.length) - 1]}` });
    }
    sections.push({ id: 'parts', side: true, title: `Showing ${shown.length} of ${all.length}`,
      blocks: [{ type: 'filters', param: 'part', options }] });
  }
  sections.push(policySection(c));
  return {
    title: 'Secrets',
    intro: `${all.length} stored, ${keyed ? 'key on this host' : 'no key'}. Write-only: bodies get them when they start, or ask for one (you allow or deny it here), and there is no way to read one back on this page.`,
    sections,
  };
}

/** Who gets this secret without asking (Always allow on a request card), each with Stop. */
function standingSection(c, name) {
  const agents = standing(c, name);
  if (!agents.length) return [];
  return [{ id: 'standing', title: 'Given without asking', blocks: [{ type: 'list', items: agents.map((agent) => ({
    text: agent, meta: `every house of ${agent} gets it when it asks`,
    act: { action: 'stop-always', label: 'Stop', tone: 'danger', fields: { name, agent },
      confirm: `${agent}'s houses will ask you for ${name} again.` },
  })) }] }];
}

/** One stored name: a Replace form and a Remove button. Never a value. */
function secretPage(c, name) {
  if (!NAME.test(name) || !names(c).includes(name)) return NOT_FOUND;
  return {
    title: name,
    intro: 'Write-only: its value is never shown, here or anywhere on this page.',
    sections: [...standingSection(c, name), { id: 'secret', blocks: [
      { type: 'form', title: 'Replace', action: 'replace', submit: 'Replace', hidden: { name },
        note: 'The old value is overwritten. Bodies pick up the new one the next time they start.',
        fields: [{ name: 'value', label: 'New value', kind: 'secret', required: true }] },
      { type: 'buttons', items: [{ action: 'remove', label: 'Remove', tone: 'danger', fields: { name },
        confirm: `Bodies started after this won't get ${name}.` }] },
    ] }],
  };
}

const MESSAGES = {
  add: (n) => `${n} is encrypted and stored. Bodies pick it up the next time they start.`,
  replace: (n) => `${n} is replaced. Bodies pick up the new value the next time they start.`,
  remove: (n) => `${n} is removed from the store.`,
};

const ANSWERS = { grant: 'Allowed', always: 'Always allowed', deny: 'Denied', revoke: 'Revoked' };

function uiAct(c, env, req) {
  const no = (message) => ({ ok: false, message, page: '' });
  if (!req) return no('That request could not be read.');
  const action = req.action;
  if (Object.hasOwn(ANSWERS, action)) {
    const id = req.fields?.id;
    if (typeof id !== 'string' || !/^q-[0-9a-f]{8}$/.test(id)) return no('That is not a request.');
    try {
      const r = answer(c, id, action);
      return { ok: true, message: action === 'always'
        ? `Allowed: ${r.agent}'s ${r.secret} for ${r.house}, and ${r.agent}'s houses get it without asking from now on.`
        : `${ANSWERS[action]}: ${r.agent}'s ${r.secret} for ${r.house}${action === 'grant' ? `, for ${r.minutes} min` : ''}.`, page: '' };
    } catch (err) { return no(err.message); }
  }
  if (action === 'stop-always') {
    const { name, agent } = req.fields && typeof req.fields === 'object' ? req.fields : {};
    // The agent is checked by exact membership in the policy's list (stopAlways), not by a pattern of its own.
    if (typeof name !== 'string' || !NAME.test(name) || typeof agent !== 'string' || agent.length > 64) return no('That is not a secret and an agent.');
    try {
      stopAlways(c, name, agent);
      return { ok: true, message: `${agent}'s houses will ask for ${name} again.`, page: '' };
    } catch (err) { return no(err.message); }
  }
  if (!Object.hasOwn(MESSAGES, action)) return no('The secrets piece has no such action.');
  const fields = req.fields && typeof req.fields === 'object' ? req.fields : {};
  const name = fields.name;
  // Never echo a name that fails the rules: whatever was typed there may be a value.
  if (typeof name !== 'string' || !NAME.test(name)) return no(`That is not a secret name. ${NAME_HINT}`);
  let value;
  if (action !== 'remove') {
    value = fields.value;
    if (typeof value !== 'string' || value === '') return no(`Nothing stored: the value for ${name} is empty.`);
    if (Buffer.byteLength(value, 'utf-8') > MAX_VALUE) return no(`Nothing stored: the value for ${name} is over 64 KB.`);
  }
  try {
    if (action === 'add') put(c, env, name, value, 'new');
    else if (action === 'replace') put(c, env, name, value, 'existing');
    else remove(c, env, name);
  } catch (err) {
    let message = err instanceof Fail && err.code === 3
      ? (action === 'add' ? `${name} already exists. To change it, use Replace on ${name} under In the store.`
        : `There is no secret named ${name}.`)
      : `Nothing changed for ${name}: ${err.message}`;
    // A tool's error text should never carry the value, but make sure.
    if (value && message.includes(value)) message = `Nothing changed for ${name}: the store could not be written.`;
    return no(message);
  }
  return { ok: true, message: MESSAGES[action](name), page: '' };
}

// ---- loom's bundle (household.md, "Export and restore") -------------------
// The part is `age -e -a -r R…` over the canonical JSON of the decrypted map:
//   {"format":"loom-secrets/1","secrets":{"<name>":"<value>", …}}  (names sorted)
// No sops metadata travels, so import needs only age and the owner's identity.
// Plaintext moves between sops and age through this process's memory and their
// stdin/stdout pipes: never argv, env, a log or a file.

const PART_FORMAT = 'loom-secrets/1';
const AGE_RECIPIENT = /^age1[0-9a-z]{20,}$/;              // X25519 or a plugin (age1yubikey1…)
const SSH_RECIPIENT = /^(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [^,\n]*)?$/;

function exportRecipients(env) {
  const raw = env.LOOM_EXPORT_RECIPIENTS;
  const list = (raw || '').split(',').map((r) => r.trim()).filter(Boolean);
  if (list.length === 0) {
    throw new Fail('refused: LOOM_EXPORT_RECIPIENTS is empty. Export needs at least one age recipient (age1…) ' +
      'to encrypt the part to; it never writes the store out in the clear.', 2);
  }
  list.forEach((r, i) => {
    if (AGE_RECIPIENT.test(r) || SSH_RECIPIENT.test(r)) return;
    // Never echo it: a private key pasted in by mistake would land in a log.
    const hint = /^AGE-SECRET-KEY-/i.test(r) ? ' It looks like a private key; pass the public one (age-keygen -y).' : '';
    throw new Fail(`refused: recipient ${i + 1} in LOOM_EXPORT_RECIPIENTS isn't an age recipient (age1…) or an ssh public key.${hint}`, 2);
  });
  return list;
}

function canonicalPart(data) {
  const secrets = {};
  for (const name of Object.keys(data).sort()) secrets[name] = data[name];
  return JSON.stringify({ format: PART_FORMAT, secrets });
}

function exportPart(c, env) {
  const recipients = exportRecipients(env);
  // No store yet: an empty part, so a restore lays down an empty store too.
  const data = decrypt(c, env);
  const part = run(c.age, ['-e', '-a', ...recipients.flatMap((r) => ['-r', r])], { input: canonicalPart(data), env });
  return { part, count: Object.keys(data).length, recipients: recipients.length };
}

async function readAll(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function openPart(c, env, identity, part) {
  const r = spawnSync(c.age, ['-d', '-i', identity], { input: part, env, encoding: 'utf-8', maxBuffer: 16 * 1024 * 1024 });
  if (r.error) throw new Fail(`can't run ${c.age}: ${r.error.message}`);
  if (r.status !== 0) {
    throw new Fail(`the part doesn't decrypt with LOOM_IMPORT_IDENTITY (${(r.stderr || '').trim().split('\n').pop()}). ` +
      'Is it the key the bundle was made for? Nothing was written.');
  }
  let doc;
  try { doc = JSON.parse(r.stdout); } catch { doc = null; }
  if (!doc || doc.format !== PART_FORMAT || !doc.secrets || typeof doc.secrets !== 'object' || Array.isArray(doc.secrets)) {
    throw new Fail(`the part decrypts but isn't a ${PART_FORMAT} part. Nothing was written.`);
  }
  for (const [name, value] of Object.entries(doc.secrets)) {
    // Names only in messages, and only names that pass the rules.
    if (!NAME.test(name)) throw new Fail('the part holds a name that fails the rules. Nothing was written.');
    if (typeof value !== 'string' || value === '') throw new Fail(`the part's value for ${name} isn't a non-empty string. Nothing was written.`);
  }
  return doc.secrets;
}

async function importPart(c, env, io, force) {
  const identity = env.LOOM_IMPORT_IDENTITY;
  if (!identity) throw new Fail('refused: LOOM_IMPORT_IDENTITY is empty. Import needs the age identity the part was encrypted to.', 2);
  if (!existsSync(identity)) throw new Fail(`refused: LOOM_IMPORT_IDENTITY names no file (${identity}).`, 2);
  const held = names(c);
  if (held.length > 0 && !force) {
    throw new Fail(`refused: the store at ${c.store} already holds ${held.length} secret(s). ` +
      'Restore is for a fresh machine; pass --force to replace the whole store with the part.', 3);
  }
  const part = await readAll(io.stdin);
  if (part.length === 0) throw new Fail('refused: no part on stdin.', 2);
  const secrets = openPart(c, env, identity, part);
  // init semantics: a 0700 dir and this machine's own 0600 key, if there isn't one.
  mkdirSync(c.dir, { recursive: true, mode: 0o700 });
  chmodSync(c.dir, 0o700);
  if (!existsSync(c.key)) { run(c.keygen, ['-o', c.key]); chmodSync(c.key, 0o600); io.stderr(`created age key ${c.key}\n`); }
  withLock(c, () => {
    if (names(c).length > 0 && !force) throw new Fail('refused: the store filled up while importing; nothing was written.', 3);
    encrypt(c, env, secrets);
  });
  return Object.keys(secrets).length;
}

function revealAllowed(io) {
  return io.env.LOOM_SECRETS_ALLOW_GET === '1' || (io.stdinIsTTY && io.stdoutIsTTY);
}

export async function main(argv, io) {
  const [cmd, ...args] = argv;
  const c = config(io.env);
  const flags = new Set(args.filter((a) => a.startsWith('--')));
  const pos = args.filter((a) => !a.startsWith('--'));
  const allow = (ok) => { for (const f of flags) if (!ok.includes(f)) throw new Fail(`unknown flag ${f}\n${USAGE}`, 2); };

  switch (cmd) {
    case undefined: case '--help': case '-h': case 'help':
      io.stdout(USAGE); return cmd ? 0 : 2;

    case 'init': {
      allow([]);
      mkdirSync(c.dir, { recursive: true, mode: 0o700 });
      chmodSync(c.dir, 0o700);
      if (existsSync(c.key)) io.stderr(`age key already at ${c.key}; leaving it\n`);
      else { run(c.keygen, ['-o', c.key]); chmodSync(c.key, 0o600); io.stderr(`created age key ${c.key}\n`); }
      if (!existsSync(c.store)) withLock(c, () => encrypt(c, io.env, {}));
      io.stdout(`${c.store}\n`);
      return 0;
    }

    case 'add': {
      allow(['--force']);
      checkName(pos[0]);
      if (pos.length > 1) {
        throw new Fail(`refusing a value in argv (it would land in ps and shell history).\n` +
          `Pipe it in instead:  printf %s "$VALUE" | loom secrets add ${pos[0]}\n` +
          `or run \`loom secrets add ${pos[0]}\` at a terminal and type it.`, 2);
      }
      const value = await readValue(io);
      if (!value) throw new Fail('empty value; nothing stored', 2);
      put(c, io.env, pos[0], value, flags.has('--force') ? 'any' : 'new');
      io.stderr(`stored ${pos[0]}\n`);
      return 0;
    }

    case 'ui': {
      // The secrets piece on loom's page (loom docs/extensions.md, "The page",
      // contract v2). Write-only: the page can add, replace and remove, and
      // nothing in it can read a value back. See README, ac-sec-ui-*.
      allow(['--json']);
      const sub = pos[0];
      if (sub === undefined) { io.stdout(JSON.stringify(uiManifest(c)) + '\n'); return 0; }
      if (pos.length > 1) throw new Fail(`usage: loom secrets ui [page|act] --json`, 2);
      if (sub === 'page') { io.stdout(JSON.stringify(uiPage(c, await readRequest(io))) + '\n'); return 0; }
      if (sub === 'act') { io.stdout(JSON.stringify(uiAct(c, io.env, await readRequest(io))) + '\n'); return 0; }
      throw new Fail(`unknown ui command ${sub}\n${USAGE}`, 2);
    }

    case 'bundle': {
      // loom's bundle seam (household.md, "Export and restore"). Namespaced so
      // it can't collide with another piece's own export/import.
      const sub = pos[0];
      if (sub === 'export') {
        // stdout is the part and nothing else.
        allow([]);
        if (pos.length > 1) throw new Fail('usage: LOOM_EXPORT_RECIPIENTS=age1… loom-secrets bundle export', 2);
        const { part, count, recipients } = exportPart(c, io.env);
        io.stdout(part);
        io.stderr(`exported ${count} secret(s), encrypted to ${recipients} recipient(s)\n`);
        return 0;
      }
      if (sub === 'import') {
        allow(['--force']);
        if (pos.length > 1) throw new Fail('usage: LOOM_IMPORT_IDENTITY=<key file> loom-secrets bundle import [--force] < part', 2);
        const count = await importPart(c, io.env, io, flags.has('--force'));
        io.stderr(`imported ${count} secret(s) into ${c.store}, encrypted to this machine's key\n`);
        return 0;
      }
      throw new Fail(`unknown bundle command ${sub ?? '(none)'}; it's bundle export or bundle import\n${USAGE}`, 2);
    }

    case 'api': {
      // loom's piece API (docs/extensions.md, "The API"): {caller, path:'run', body:{argv}}.
      //   request NAME --why TEXT [--minutes N]   ask for a secret (a house's own token only)
      //   get NAME                                 read it, with a live grant for this house
      //   status                                   this house's requests
      allow(['--json']);
      const req = await readRequest(io);
      io.stdout(JSON.stringify(await apiAnswer(c, io.env, req)) + '\n');
      return 0;
    }

    case 'list': {
      allow(['--json']);
      const n = names(c);
      io.stdout(flags.has('--json') ? JSON.stringify(n) + '\n' : n.map((x) => x + '\n').join(''));
      return 0;
    }

    case 'rm': {
      allow([]);
      checkName(pos[0]);
      remove(c, io.env, pos[0]);
      io.stderr(`removed ${pos[0]}\n`);
      return 0;
    }

    case 'get': {
      allow(['--reveal']);
      checkName(pos[0]);
      if (!flags.has('--reveal')) throw new Fail('get prints a secret; pass --reveal to mean it', 2);
      if (!revealAllowed(io)) {
        throw new Fail('refused: get --reveal needs an interactive terminal, or LOOM_SECRETS_ALLOW_GET=1 from the host side. ' +
          'A body gets secrets injected into its runtime, not read out of the store.', 4);
      }
      const data = decrypt(c, io.env);
      if (!Object.hasOwn(data, pos[0])) throw new Fail(`no secret named ${pos[0]}`, 3);
      io.stdout(data[pos[0]] + (io.stdoutIsTTY ? '\n' : ''));
      return 0;
    }

    case 'podman': {
      allow([]);
      checkName(pos[0]);
      if (!pos[1] || !NAME.test(pos[1])) throw new Fail('usage: loom secrets podman <name> <podman-secret-name>', 2);
      // The same gate as get --reveal: with $LOOM_SECRETS_PODMAN pointing at
      // `cat`, injection is just another way to print the value.
      if (!revealAllowed(io)) {
        throw new Fail('refused: podman injection is host-side only (an interactive terminal, or LOOM_SECRETS_ALLOW_GET=1 from the host side).', 4);
      }
      const data = decrypt(c, io.env);
      if (!Object.hasOwn(data, pos[0])) throw new Fail(`no secret named ${pos[0]}`, 3);
      // podman, like sops, wants a real pipe on stdin, not node's socketpair.
      run('sh', ['-c', 'cat | "$0" "$@"', c.podman, 'secret', 'create', '--replace', pos[1], '-'],
        { input: data[pos[0]], env: io.env });
      io.stderr(`podman secret ${pos[1]} <- ${pos[0]}\n`);
      return 0;
    }

    default:
      throw new Fail(`unknown command ${cmd}\n${USAGE}`, 2);
  }
}

async function apiAnswer(c, env, req) {
  const refuse = (status, error) => ({ status, body: { error } });
  if (!req || req.path !== 'run') return refuse(404, 'the one call is run');
  const argv = req.body?.argv;
  if (!Array.isArray(argv) || !argv.length || argv.length > 8 || !argv.every((a) => typeof a === 'string' && a.length <= 600)) {
    return refuse(400, 'argv is: request NAME --why TEXT [--minutes N] | get NAME | status');
  }
  const flag = (n) => { const i = argv.indexOf(n); return i > 0 && i + 1 < argv.length ? argv[i + 1] : undefined; };
  const ok = (stdout) => ({ status: 200, body: { exit: 0, stdout, stderr: '' } });
  const fail = (e) => (e instanceof RequestError && e.status !== 403 && e.status !== 404
    ? { status: 200, body: { exit: 1, stdout: '', stderr: `secrets: ${e.message}\n` } }
    : refuse(e.status ?? 500, e.message));
  try {
    if (argv[0] === 'request' && argv[1] && NAME.test(argv[1])) {
      const m = flag('--minutes');
      const r = request(c, req.caller, { secret: argv[1], why: flag('--why'), minutes: m === undefined ? undefined : Number(m) }, names(c));
      const say = r.state === 'granted' ? `granted: ${r.secret} for this house until ${r.expires} (\`secret get ${r.secret}\`)`
        : r.state === 'pending' ? `asked the owner (request ${r.id}); \`secret get ${r.secret}\` works once they allow it`
          : `denied: the policy doesn't give ${r.secret} out`;
      return { status: 200, body: { exit: r.state === 'denied' ? 1 : 0, stdout: `${say}\n`, stderr: '' } };
    }
    if (argv[0] === 'get' && argv[1] && NAME.test(argv[1]) && argv.length === 2) {
      mayRead(c, req.caller, argv[1]);
      const data = decrypt(c, env);
      if (!Object.hasOwn(data, argv[1])) throw new RequestError(`there is no secret named ${argv[1]}`, 404);
      return ok(data[argv[1]]);
    }
    if (argv[0] === 'status' && argv.length === 1) return ok(JSON.stringify(mine(c, req.caller)) + '\n');
    return refuse(400, 'argv is: request NAME --why TEXT [--minutes N] | get NAME | status');
  } catch (e) { return fail(e); }
}

export function realIO() {
  return {
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    stdin: process.stdin,
    stdinIsTTY: Boolean(process.stdin.isTTY),
    stdoutIsTTY: Boolean(process.stdout.isTTY),
    env: process.env,
  };
}

// Real paths: an npm bin (or loom-secrets on PATH) is a symlink to this file.
const isMain = (() => {
  try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); }
  catch { return false; }
})();
if (isMain) {
  const io = realIO();
  main(process.argv.slice(2), io).then(
    (code) => process.stdout.write('', () => process.exit(code)),
    (err) => { io.stderr(`loom secrets: ${err.message}\n`); process.exit(err instanceof Fail ? err.code : 1); },
  );
}

export { Fail };
