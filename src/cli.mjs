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
import { all as allRequests, answer, mayRead, mine, readPolicy, request, RequestError, standing, stopAlways, forgetStanding, stateOf, may, setHouses, setAlways, auditIssue, record } from './requests.mjs';

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const STORE = 'store.sops.json';
const KEY = 'age.key';

const USAGE = `Usage: loom secrets <command> [args]

  init                          Create the age key and an empty store
  add <name> [--force]          Store a value read from stdin (or a no-echo prompt)
  list [--json]                 Names only (never decrypts)
  state <request id>            A request's state (pending, granted, denied,
                                revoked, expired), for the clock parked on it
  rm <name>                     Delete a secret
  get <name> --reveal           Print a value: only at a terminal, or with
                                LOOM_SECRETS_ALLOW_GET=1 set by the host side
  podman <name> <podman-name>   Put the value into a podman secret, unprinted
  may <agent> <name> [--json]   Whether that agent's houses get it when they start:
                                allowed, denied or ask (the policy's say; never a value)
  issue <name> --agent A [--house H]
                                The value, for a house the runtime is starting, when
                                \`may\` says allowed: only from the runtime's own process
                                (loom names it: LOOM_PIECE_NAME runtime), no flag to set
  policy houses <name> <agent> [--off]
                                The owner's: that agent's houses get it at start (or stop)
  policy houses-import          The owner's: {"<agent>": ["<name>", ...]} on stdin, each
                                allowed (the runtime's old map: loom runtime secrets-map --json)
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
    const had = Object.hasOwn(data, name);
    if (mode === 'new' && had) throw new Fail(`${name} already exists (pass --force to replace it)`, 3);
    if (mode === 'existing' && !had) throw new Fail(`no secret named ${name}`, 3);
    data[name] = value;
    encrypt(c, env, data);
    // When it was set or changed, for its page (the name and when, never the value).
    record(c, { event: 'set', secret: name, how: had ? 'replace' : 'add' });
  });
}

function remove(c, env, name) {
  checkName(name);
  withLock(c, () => {
    const data = decrypt(c, env);
    if (!Object.hasOwn(data, name)) throw new Fail(`no secret named ${name}`, 3);
    delete data[name];
    encrypt(c, env, data);
    record(c, { event: 'removed', secret: name });
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
    // The store is the household's (under Setup); what each agent gets, and its requests, are on its own tab.
    tab: { label: 'Secrets', kind: 'setting' },
    agentTab: { label: 'Secrets' },
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

/** An agent's name as a name in a sentence: "art" -> "Art". The id itself (fields, pages) stays as it is. */
const named = (agent) => String(agent).charAt(0).toUpperCase() + String(agent).slice(1);

/** A time in the box's local time, 12-hour: "12:09 PM" today, "Oct 31, 12:09 PM" another day (with the year if not this one). */
function when(iso, now = new Date()) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const clock = d.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' }).replace(/\s/g, ' ');
  const ymd = (x) => x.toLocaleDateString('en-CA');
  if (ymd(d) === ymd(now)) return clock;
  const sameYear = d.toLocaleDateString('en-US', { year: 'numeric' }) === now.toLocaleDateString('en-US', { year: 'numeric' });
  return `${d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', ...(sameYear ? {} : { year: 'numeric' }) })}, ${clock}`;
}

/** A request's state as the page says it. */
const STATE = { pending: 'Waiting on you', granted: 'Granted', expired: 'Expired', denied: 'Denied', revoked: 'Revoked' };

/** Who decided, as the history says it: the member who answered, or the policy. */
const by = (r) => (r.by === 'owner' ? (r.who ? ` by ${r.who}` : '') : ' (by the policy)');

/** The member acting on loom's page (its caller, in a household), or none. */
const whoOf = (req) => (req?.caller?.kind === 'owner' && typeof req.caller.who === 'string' && /^[a-z0-9]+(-[a-z0-9]+)*$/.test(req.caller.who) ? req.caller.who : undefined);

const OUTCOME = {
  granted: (r) => r.always ? `Allowed${by(r)}, and from now on without asking.` : `Allowed for ${r.minutes} min${by(r)}.`,
  expired: (r) => `Allowed for ${r.minutes} min${by(r)}; it ran out.`,
  denied: (r) => `Denied${by(r)}.`,
  revoked: () => 'Allowed, then revoked.',
};

function answeredRequests(c) {
  return allRequests(c).filter((r) => OUTCOME[r.state]).slice(0, 20).map((r) => ({
    text: `${named(r.agent)} asked for ${r.secret}: “${r.why}”`.slice(0, 300), outcome: OUTCOME[r.state](r),
    at: r.decided ?? r.at, kind: 'permission', agent: r.agent, page: secretLink(r.secret),
  }));
}

/** A request's three answers, as an ask's actions and as the buttons in its sheet. */
const answers = (r) => [
  { action: 'grant', label: `Allow ${r.minutes} min`, tone: 'primary', fields: { id: r.id } },
  { action: 'always', label: `Always allow ${named(r.agent)}`, fields: { id: r.id },
    confirm: `Every house of ${named(r.agent)} gets ${r.secret} without asking, 8 hours at a time, until you stop it on the secret's page.` },
  { action: 'deny', label: 'Deny', tone: 'danger', fields: { id: r.id } },
];

function pendingAsks(c) {
  return allRequests(c).filter((r) => r.state === 'pending').slice(0, 10).map((r) => ({
    text: `${named(r.agent)} asks for ${r.secret}`,
    meta: `For ${r.minutes} min: “${r.why}”`,
    tone: 'warn', at: r.at, agent: r.agent, page: secretLink(r.secret), kind: 'permission',
    actions: answers(r),
  }));
}

/** A secret's own page: its name rides in the query (loom's page paths are lowercase, names needn't be). */
const secretLink = (name) => `secret?name=${encodeURIComponent(name)}`;

/** How long ago, in words: "just now", "5 min ago", "3 hours ago", "yesterday", "4 days ago", else the date. */
function ago(iso, now = new Date()) {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return '';
  const s = Math.max(0, (now.getTime() - t) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86_400) { const h = Math.floor(s / 3600); return `${h} hour${h === 1 ? '' : 's'} ago`; }
  const d = Math.floor(s / 86_400);
  if (d === 1) return 'yesterday';
  if (d < 7) return `${d} days ago`;
  return `on ${when(iso, now).replace(/, \d{1,2}:\d{2} [AP]M$/, '')}`;
}

// The audit lines the page reads (a cheap filter before JSON.parse): uses, and when a value was set or removed.
const RECORD_EVENTS = ['"issue"', '"read"', '"host-read"', '"set"', '"removed"'];

/**
 * What the record says of each name, from the audit (names and times, never a value): which agents' houses were
 * given it and when (a house starting, or a read with a grant), when loom's machine read it (get, podman), and when
 * it was set or changed. A removal clears a name's past.
 */
function usage(c) {
  const out = new Map();
  let text = '';
  try { text = readFileSync(join(c.dir, 'audit.jsonl'), 'utf-8'); } catch { return out; }
  const of = (name) => { let u = out.get(name); if (!u) out.set(name, u = { agents: new Map(), host: null, set: null }); return u; };
  for (const line of text.split('\n')) {
    if (!RECORD_EVENTS.some((k) => line.includes(k))) continue;
    let e;
    try { e = JSON.parse(line); } catch { continue; }
    if (typeof e?.secret !== 'string' || typeof e.at !== 'string') continue;
    if (e.event === 'removed') { out.delete(e.secret); continue; }
    if (e.event === 'set') { of(e.secret).set = { at: e.at, how: e.how }; continue; }
    if (e.event === 'host-read') { const u = of(e.secret); if (!u.host || e.at > u.host.at) u.host = { at: e.at, how: e.how }; continue; }
    if ((e.event === 'issue' || e.event === 'read') && typeof e.agent === 'string') {
      const u = of(e.secret);
      const prev = u.agents.get(e.agent);
      if (!prev || e.at > prev.at) u.agents.set(e.agent, { at: e.at, how: e.event });
    }
  }
  return out;
}

/** The latest a house had it: { at, agent, how } or undefined. */
function lastHouse(u) {
  let best;
  for (const [agent, x] of u?.agents ?? []) if (!best || x.at > best.at) best = { ...x, agent };
  return best;
}

/** A list row's last line: the latest a house or loom's machine had it. */
function usedWords(u) {
  const h = lastHouse(u);
  if (u?.host && (!h || u.host.at > h.at)) return `Last read on loom's machine ${ago(u.host.at)}`;
  return h ? `Last given to ${named(h.agent)}'s house ${ago(h.at)}` : 'Not given to a house yet';
}

/** Whether anything has had it: a house, or loom's machine. */
const everUsed = (u) => Boolean(u && (u.agents.size || u.host));

const YEAR_MS = 365 * 86_400_000;

/** The agents the store knows of: in the policy or in a request. */
function knownAgents(c) {
  const p = readPolicy(c);
  return [...new Set(allRequests(c).map((r) => r.agent)
    .concat(Object.values(p.secrets).flatMap((r) => (r && typeof r === 'object' ? [...(Array.isArray(r.agents) ? r.agents : []), ...(Array.isArray(r.houses) ? r.houses : [])] : []))))]
    .filter((a) => typeof a === 'string' && /^[a-z][a-z0-9-]{0,39}$/.test(a)).sort();
}

/** What one agent gets of one secret: at start (houses), when a house asks without you (auto), never, or neither. */
function givenTo(rule, agent) {
  const r = rule && typeof rule === 'object' ? rule : {};
  if (r.grant === 'never') return { never: true, start: false, auto: false };
  return { never: false, start: Array.isArray(r.houses) && r.houses.includes(agent),
    auto: r.grant === 'auto' && Array.isArray(r.agents) && r.agents.includes(agent) };
}

const givesWords = (g) => (g.never ? 'Never given out' : g.start && g.auto ? 'At start, and when a house asks'
  : g.start ? 'When a house starts' : g.auto ? 'When a house asks, without you' : 'Asks you first');

/** Who gets a secret, in words: "Art at start, Mark when asked", "Never given out", "Asks you first". */
function whoGetsWords(policy, agents, name) {
  const rule = policy.secrets[name];
  if (rule?.grant === 'never') return 'Never given out';
  const parts = agents.map((a) => [a, givenTo(rule, a)]).filter(([, g]) => g.start || g.auto)
    .map(([a, g]) => `${named(a)} ${g.start && g.auto ? 'at start and when asked' : g.start ? 'at start' : 'when asked'}`);
  return parts.length ? parts.join(', ') : 'Asks you first';
}

/** Which way a secret is given, for the store's filter. */
function givenKind(policy, agents, name) {
  const rule = policy.secrets[name];
  if (rule?.grant === 'never') return 'never';
  const gs = agents.map((a) => givenTo(rule, a));
  return gs.some((g) => g.start) ? 'start' : gs.some((g) => g.auto) ? 'asked' : 'ask';
}

/** The place a request came from, in words: "Art's house", "Art's slack house". */
const houseWords = (r) => `${named(r.agent)}'s ${r.service ? `${String(r.service).replace(/-/g, ' ')} ` : ''}house`;

/** Requests waiting on the owner: a row each, its answers in a sheet (the Inbox has the same card). */
function waitingSection(rs) {
  const waiting = rs.filter((r) => r.state === 'pending');
  if (!waiting.length) return [];
  return [{ id: 'waiting', title: 'Waiting on you', tone: 'warn', blocks: [{ type: 'panel', rows: waiting.slice(0, 20).map((r) => ({
    label: `${named(r.agent)} asks for ${r.secret}`, agent: r.agent, tone: 'warn',
    value: `“${r.why}”`, detail: `For ${r.minutes} min · asked ${ago(r.at)}`,
    sheet: { title: `${named(r.agent)} asks for ${r.secret}`, blocks: [
      { type: 'text', text: `“${r.why}”` },
      { type: 'text', tone: 'muted', text: `From ${houseWords(r)}, ${ago(r.at)}. Allowing it lets that house read ${r.secret} for ${r.minutes} min.` },
      { type: 'buttons', items: answers(r) },
    ] },
  })) }] }];
}

/** Live grants, each a row with Revoke. */
function liveSection(rs) {
  const live = rs.filter((r) => r.state === 'granted');
  if (!live.length) return [];
  return [{ id: 'grants', title: 'Live grants', blocks: [{ type: 'panel', rows: live.slice(0, 50).map((r) => ({
    label: `${houseWords(r)} · ${r.secret}`, agent: r.agent, tone: 'ok',
    value: `Can read it until ${when(r.expires)}`, detail: `“${r.why}”`,
    act: { action: 'revoke', label: 'Revoke', tone: 'danger', fields: { id: r.id }, confirm: `That house won't be able to read ${r.secret} again.` },
  })) }] }];
}

/** What was asked before and how it went: each house's reason whole, never cut. */
function pastSection(rs, { withSecret }) {
  const past = rs.filter((r) => r.state !== 'pending' && r.state !== 'granted');
  if (!past.length) return [];
  return [{ id: 'requests', title: 'Asked before', fold: 'open', blocks: [{ type: 'list', wrap: true, items: past.slice(0, 60).map((r) => ({
    text: withSecret ? r.secret : houseWords(r), agent: r.agent,
    meta: `${STATE[r.state] ?? r.state} · ${ago(r.decided ?? r.at)} · “${r.why}”`,
    tone: r.state === 'denied' || r.state === 'revoked' ? 'muted' : undefined,
  })) }] }];
}

/** Who gets what without asking (policy.json), for the household: what everything else does, and what's never given. */
function policySection(c, p = readPolicy(c)) {
  const never = Object.entries(p.secrets).filter(([, r]) => r && r.grant === 'never').map(([name]) => name);
  return { id: 'policy', side: true, title: 'Who gets what', blocks: [{ type: 'panel', rows: [
    { label: 'A secret not given out', value: p.default === 'ask' ? 'A house asks you for it' : p.default === 'auto' ? 'Any house gets it when it asks' : 'Refused' },
    { label: 'Never given out', value: never.length ? never.join(', ') : 'Nothing' },
    { label: 'The policy file', value: 'Where these rules are kept',
      sheet: { title: 'The policy file', blocks: [{ type: 'code', label: 'policy.json', text: join(c.dir, 'policy.json') },
        { type: 'text', tone: 'muted', text: 'Each secret’s rule: houses (given when a house starts), grant auto with agents (given when a house asks), or never.' }] } },
  ] }] };
}

/** An agent's Secrets tab (loom docs/extensions.md, agentTab): what it gets, what's waiting, what's live, what it asked. */
function agentPage(c, agent) {
  const p = readPolicy(c);
  const uses = usage(c);
  const gets = names(c).map((name) => [name, givenTo(p.secrets[name], agent)]).filter(([, g]) => !g.never && (g.start || g.auto));
  const rs = allRequests(c).filter((r) => r.agent === agent);
  const sections = [...waitingSection(rs), { id: 'gets', title: `What ${named(agent)} gets`, blocks: gets.length
    ? [{ type: 'panel', rows: gets.map(([name, g]) => ({ label: name, value: givesWords(g), detail: agentUsed(uses.get(name), agent), page: secretLink(name) })) }]
    : [{ type: 'text', tone: 'muted', text: `Nothing: ${named(agent)}'s houses ask you for every secret they don't start with.` }] },
  ...liveSection(rs), ...pastSection(rs, { withSecret: true })];
  if (!rs.length) sections.push({ id: 'requests', title: 'Asked before', blocks: [{ type: 'text', tone: 'muted', text: 'No requests yet.' }] });
  return { title: 'Secrets', intro: `What ${named(agent)}'s houses get, and what they've asked for. Values are never shown.`, sections };
}

const WHO_FILTER = [
  { value: '', label: 'All' }, { value: 'start', label: 'At start' }, { value: 'asked', label: 'Without asking' },
  { value: 'ask', label: 'Asks you' }, { value: 'never', label: 'Never' },
];

/** One agent's use of a secret, for that agent's tab. */
const agentUsed = (u, agent) => { const a = u?.agents.get(agent); return a ? `Last given to ${named(agent)}'s house ${ago(a.at)}` : 'Not given to a house yet'; };

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const listLink = (of) => `list?of=${encodeURIComponent(of)}`;

/**
 * The store in groups, by who can use each secret (one secret can be in more than one): each agent (its houses get
 * it at start or without asking), loom's machine (read there, on record), only when you say yes (no agent gets it
 * without asking), never given out. And what needs a look: names a house should get that aren't stored, secrets
 * nobody has used, and secrets not changed in a year (when the record knows). Names only; never a value.
 */
function storeView(c) {
  const policy = readPolicy(c);
  const agents = knownAgents(c);
  const uses = usage(c);
  const all = names(c);
  const stored = new Set(all);
  const now = Date.now();
  const never = all.filter((n) => policy.secrets[n]?.grant === 'never');
  const byAgent = agents.map((a) => [a, all.filter((n) => { const g = givenTo(policy.secrets[n], a); return !g.never && (g.start || g.auto); })]);
  const someone = new Set(byAgent.flatMap(([, ns]) => ns));
  const askOnly = all.filter((n) => policy.secrets[n]?.grant !== 'never' && !someone.has(n));
  const host = all.filter((n) => uses.get(n)?.host);
  // Not used: no agent gets it without asking, and nothing on record has had it (a house, or loom's machine).
  const unused = askOnly.filter((n) => !everUsed(uses.get(n)));
  const old = all.filter((n) => { const set = uses.get(n)?.set; return set && now - Date.parse(set.at) > YEAR_MS; });
  // Missing: the rules give it to an agent's houses at start or without asking, and it isn't in the store (the
  // runtime would try to hand it to that agent's next house, and fail).
  const missing = new Map();
  for (const [n, rule] of Object.entries(policy.secrets)) {
    if (stored.has(n) || !NAME.test(n) || !rule || typeof rule !== 'object' || rule.grant === 'never') continue;
    const to = [...new Set([...(Array.isArray(rule.houses) ? rule.houses : []), ...(rule.grant === 'auto' && Array.isArray(rule.agents) ? rule.agents : [])])]
      .filter((a) => typeof a === 'string' && /^[a-z][a-z0-9-]{0,39}$/.test(a));
    if (to.length) missing.set(n, `The rules give it to ${to.map(named).join(' and ')}'s houses`);
  }
  return { policy, agents, uses, all, never, byAgent, askOnly, host, unused, old, missing: new Map([...missing].sort(([x], [y]) => (x < y ? -1 : 1))) };
}

/** What happens to a secret no agent is given by name: the policy's default (README, "Requests"). */
function otherWords(policy) {
  if (policy.default === 'auto') return { title: 'Any house that asks', detail: 'Given to a house when it asks, without you', intro: 'Any house that asks gets one, without asking you (the policy\'s default).' };
  if (policy.default === 'never') return { title: 'Not given out', detail: 'Refused to every house (the policy\'s default)', intro: 'The policy\'s default refuses them to every house.' };
  return { title: 'Only when you say yes', detail: 'A house asks you each time', intro: 'A house asks you each time.' };
}

/** A row for a name the rules give out that isn't stored: tap to add it. */
const missingRow = (v, name) => ({ label: name, tone: 'bad', value: 'Not in the store', detail: `${v.missing.get(name)}. Tap to add it.`, edit: addMissing(name) });

/** An add form for a name the rules want and the store doesn't have. */
const addMissing = (name) => ({ action: 'add', title: `Add ${name}`, submit: 'Save', hidden: { name },
  fields: [{ name: 'value', label: 'Value', kind: 'secret', required: true, hint: 'It goes straight into the encrypted store and is never shown again.' }] });

/** The groups a list page can show, by `of`. */
function groupOf(v, of) {
  if (of === 'all') return { title: 'All secrets', intro: 'Every secret in the store.', names: v.all };
  if (of === 'never') return { title: 'Never given out', intro: 'The rules never give these to a house, at start or by asking.', names: v.never };
  if (of === 'ask') return { title: otherWords(v.policy).title, intro: `No agent is given these by name. ${otherWords(v.policy).intro}`, names: v.askOnly };
  if (of === 'loom') return { title: "Loom's machine", intro: "Read on loom's machine itself (a host script, or podman), on record.", names: v.host };
  if (of === 'unused') return { title: 'Not used by anyone', intro: "No agent gets these without asking, and nothing on record has had them: no house, and not loom's machine. Remove what's done with. Reads on loom's machine itself are on record from this version of the piece on, so a secret only a host script reads leaves this list the next time it's read.", names: v.unused };
  if (of === 'old') return { title: 'Not changed in a year', intro: 'Set over a year ago, by the record. Worth replacing if they can be rotated.', names: v.old };
  if (of === 'missing') return { title: 'Not in the store', intro: 'The rules give these to a house, and they are not stored. Add each, or stop giving it out on the policy file.', names: [...v.missing.keys()], missing: true };
  const m = /^agent:([a-z][a-z0-9-]{0,39})$/.exec(of);
  const found = m && v.byAgent.find(([a]) => a === m[1]);
  if (found) return { title: `${named(found[0])}'s secrets`, intro: `What ${named(found[0])}'s houses get: at start, or when they ask without asking you.`, names: found[1], agent: found[0] };
  return null;
}

/** A row of the store: its name, who gets it, when it was last used; a tap to its own page. */
const storeRow = (v, name) => ({ label: name, value: whoGetsWords(v.policy, v.agents, name), detail: usedWords(v.uses.get(name)), page: secretLink(name) });

/** The index: what needs a look first, then the store as groups (a row each, with a count), then Add. */
function indexPage(c, v) {
  const keyed = existsSync(c.key);
  const sections = [];
  if (!keyed) sections.push({ id: 'key', blocks: [{ type: 'callout', tone: 'bad', title: 'No age key',
    text: `There is no age key at ${c.key}, so nothing can be stored. Run: loom secrets init` }] });
  const rs = allRequests(c);
  sections.push(...waitingSection(rs));
  const look = [];
  const missing = [...v.missing];
  if (missing.length && missing.length <= 3) {
    for (const [name] of missing) look.push(missingRow(v, name));
  } else if (missing.length) {
    look.push({ label: 'Not in the store', tone: 'bad', value: plural(missing.length, 'secret'), detail: 'A house is meant to get them, and they are not stored', page: listLink('missing') });
  }
  if (v.old.length) look.push({ label: 'Not changed in a year', tone: 'warn', value: plural(v.old.length, 'secret'), detail: 'Worth replacing if they can be rotated', page: listLink('old') });
  if (v.unused.length) look.push({ label: 'Not used by anyone', value: plural(v.unused.length, 'secret'), detail: "No agent gets them, and nothing on record has had them", page: listLink('unused') });
  sections.push({ id: 'look', title: 'Needs a look', blocks: look.length
    ? [{ type: 'panel', rows: look }]
    : [{ type: 'text', tone: 'muted', text: rs.some((r) => r.state === 'pending') ? 'Nothing else.' : 'Nothing: every secret a house is meant to get is stored, and each one is used.' }] });
  // Who can use them: a row a group, with its count. A secret given to two agents is in both.
  const groups = v.byAgent.map(([a, ns]) => {
    const gs = ns.map((n) => givenTo(v.policy.secrets[n], a));
    const start = gs.filter((g) => g.start).length;
    const auto = gs.filter((g) => g.auto && !g.start).length;
    return { label: named(a), agent: a, value: plural(ns.length, 'secret'),
      detail: ns.length ? [start && `${start} at start`, auto && `${auto} when asked, without you`].filter(Boolean).join(', ') : 'Asks you for each one',
      page: listLink(`agent:${a}`) };
  });
  groups.push({ label: "Loom's machine", value: plural(v.host.length, 'secret'), detail: v.host.length ? 'Read there (a host script, or podman)' : 'None read there on record yet',
    ...(v.host.length ? { page: listLink('loom') } : {}) });
  groups.push({ label: otherWords(v.policy).title, value: plural(v.askOnly.length, 'secret'), detail: otherWords(v.policy).detail, page: listLink('ask') });
  if (v.never.length) groups.push({ label: 'Never given out', value: plural(v.never.length, 'secret'), detail: 'The rules refuse every house', page: listLink('never') });
  groups.push({ label: 'All secrets', value: String(v.all.length), detail: 'Find one by name', page: listLink('all') });
  sections.push({ id: 'groups', title: 'Who can use them', blocks: v.all.length
    ? [{ type: 'panel', rows: groups }]
    : [{ type: 'text', tone: 'muted', text: 'Nothing stored yet.' }] });
  // Add a secret: the page's one primary action, a sheet with the name and the value.
  sections.push({ id: 'add', blocks: [{ type: 'panel', rows: [{
    label: 'Add a secret', value: 'Stored encrypted. Its value is never shown again.',
    edit: { action: 'add', title: 'Add a secret', submit: 'Save',
      fields: [
        { name: 'name', label: 'Name', kind: 'text', hint: NAME_HINT, required: true },
        { name: 'value', label: 'Value', kind: 'secret', required: true,
          hint: 'It goes straight into the encrypted store and is never shown again. One line, 64 KB at most; for a multi-line value (a JSON key, an .env), pipe it in: loom secrets add <name>' },
      ] },
  }] }] });
  sections.push(policySection(c, v.policy));
  return {
    title: 'Secrets',
    intro: `${v.all.length} stored, ${keyed ? 'key on this host' : 'no key'}. Write-only: houses get them when they start, or ask for one, and there is no way to read one back here.`,
    sections,
  };
}

/** One group's secrets: a row each to its page; the whole store also has the filter and search. Parts past 200. */
function listPage(c, v, query) {
  const g = groupOf(v, typeof query.of === 'string' ? query.of : '');
  if (!g) return NOT_FOUND;
  const isAll = query.of === 'all';
  const who = isAll && WHO_FILTER.some((o) => o.value && o.value === query.who) ? query.who : '';
  const q = isAll && typeof query.q === 'string' ? query.q.trim().toLowerCase().slice(0, 64) : '';
  const matching = g.names.filter((name) => (!q || name.toLowerCase().includes(q)) && (!who || givenKind(v.policy, v.agents, name) === who));
  const parts = Math.max(1, Math.ceil(matching.length / PER_PART));
  let part = /^[1-9][0-9]{0,5}$/.test(String(query.part ?? '')) ? Number(query.part) : 1;
  if (part > parts) part = 1;
  const shown = matching.slice((part - 1) * PER_PART, part * PER_PART);
  const store = [];
  if (isAll && g.names.length > 8) store.push({ type: 'filters', param: 'who', search: 'Find a secret', options: WHO_FILTER });
  store.push(shown.length
    ? { type: 'panel', rows: shown.map((name) => (g.missing
      ? missingRow(v, name) : storeRow(v, name))) }
    : { type: 'text', tone: 'muted', text: g.names.length ? 'No secret matches.' : 'None.' });
  const sections = [{ id: 'store', title: matching.length === g.names.length ? `${g.title} · ${g.names.length}` : `${matching.length} of ${g.names.length}`, blocks: store }];
  if (parts > 1) {
    const options = [];
    for (let p = 1; p <= parts; p++) {
      const from = (p - 1) * PER_PART;
      options.push({ value: p === 1 ? '' : String(p),
        label: `${matching[from]} to ${matching[Math.min(from + PER_PART, matching.length) - 1]}` });
    }
    sections.push({ id: 'parts', side: true, title: `Showing ${shown.length} of ${matching.length}`,
      blocks: [{ type: 'filters', param: 'part', options }] });
  }
  // An agent's requests and grants are on its own Secrets tab.
  if (g.agent) sections.push({ id: 'agent', side: true, blocks: [{ type: 'panel', rows: [
    { label: `${named(g.agent)}'s Secrets tab`, agent: g.agent, value: 'Its requests, live grants and what it asked before', page: `agent:${g.agent}` }] }] });
  return { title: g.title, intro: `${g.intro} Values are never shown.`, sections };
}

function uiPage(c, req, env = {}) {
  if (!req || typeof req.path !== 'string') return NOT_FOUND;
  const scope = typeof env.LOOM_SCOPE === 'string' && /^[a-z][a-z0-9-]{0,39}$/.test(env.LOOM_SCOPE) ? env.LOOM_SCOPE : '';
  const query = req.query && typeof req.query === 'object' ? req.query : {};
  if (req.path === 'secret') return secretPage(c, String(query.name ?? ''), scope);
  // The household's store, in groups, is the household's; an agent's tab is its own (agentPage).
  if (req.path === 'list') return scope ? NOT_FOUND : listPage(c, storeView(c), query);
  if (req.path !== '') return NOT_FOUND;
  if (scope) return agentPage(c, scope);
  return indexPage(c, storeView(c));
}

/** Where a secret is used, in words: each agent's houses and loom's machine, latest first. */
function whereWords(u) {
  const places = [...(u?.agents ?? [])].map(([agent, x]) => ({ at: x.at, text: `${named(agent)}'s houses, ${ago(x.at)}` }));
  if (u?.host) places.push({ at: u.host.at, text: `loom's machine, ${ago(u.host.at)}` });
  places.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
  return places.map((p, i) => (i ? p.text : p.text.charAt(0).toUpperCase() + p.text.slice(1))).join('; ');
}

const SET_WORDS = { add: 'Added', replace: 'Changed', restore: 'Restored from a bundle' };

/** One stored name: where it's used, who can read it (a switch for each way), when it was set, its grants, Replace and Remove. Never a value. */
function secretPage(c, name, scope = '') {
  if (!NAME.test(name) || !names(c).includes(name)) return NOT_FOUND;
  const policy = readPolicy(c);
  const rule = policy.secrets[name];
  // On an agent's tab, only that agent's use (the household's view is the household's).
  const whole = usage(c).get(name);
  const u = scope ? (whole && { agents: new Map(whole.agents.has(scope) ? [[scope, whole.agents.get(scope)]] : []), host: null, set: whole.set }) : whole;
  const latest = lastHouse(u);
  const hostLast = u?.host && (!latest || u.host.at > latest.at);
  const rs = allRequests(c).filter((r) => r.secret === name && (!scope || r.agent === scope));
  const sections = [...waitingSection(rs)];
  sections.push({ id: 'secret', blocks: [{ type: 'panel', rows: [
    scope
      ? { label: 'Value', value: 'Hidden. It’s never shown, here or anywhere.', detail: 'Replace or remove it on the household’s Secrets page.', page: `household:${secretLink(name)}` }
      : { label: 'Value', value: 'Hidden. It’s never shown, here or anywhere.', detail: 'Tap to replace it.',
        edit: { action: 'replace', title: `Replace ${name}`, submit: 'Replace', hidden: { name },
          fields: [{ name: 'value', label: 'New value', kind: 'secret', required: true,
            hint: 'The old value is overwritten. Houses pick up the new one the next time they start.' }] } },
    { label: 'Where it’s used', value: everUsed(u) ? whereWords(u) : 'Not given to a house yet',
      ...(hostLast ? { detail: u.host.how === 'podman' ? 'Last put into a podman secret' : 'Last read by a host script, or at a terminal' }
        : latest ? { detail: latest.how === 'issue' ? 'Last given when a house started' : 'Last read with a grant' } : {}) },
    { label: 'Set', value: u?.set ? `${SET_WORDS[u.set.how] ?? 'Set'} ${ago(u.set.at)}` : 'Not on record',
      detail: u?.set ? when(u.set.at) : 'It was stored before the piece kept a record of changes.' },
  ] }] });
  const agents = scope ? [scope] : knownAgents(c);
  const rows = rule?.grant === 'never'
    ? [{ label: 'Every agent', value: 'Never given out', detail: 'The policy file says so; no house gets it, at start or by asking.' }]
    : agents.flatMap((a) => {
      const g = givenTo(rule, a);
      return [
        { label: 'When a house starts', agent: a, value: g.start ? `${named(a)}'s houses get it` : `${named(a)}'s houses start without it`,
          toggle: { action: 'houses', on: g.start, fields: { name, agent: a } } },
        { label: 'When a house asks', agent: a, value: g.auto ? `${named(a)}'s houses get it without asking you, 8 hours at a time` : 'It asks you first',
          toggle: { action: 'auto', on: g.auto, fields: { name, agent: a } } },
      ];
    });
  if (rule?.grant !== 'never' && !scope) rows.push({ label: agents.length ? 'Any other house' : 'Any house',
    value: policy.default === 'auto' ? 'Gets it when it asks' : policy.default === 'never' ? 'Refused' : 'Asks you first' });
  if (rows.length) sections.push({ id: 'who', title: 'Who can read it', blocks: [{ type: 'panel', rows }] });
  sections.push(...liveSection(rs), ...pastSection(rs, { withSecret: false }));
  if (!scope) sections.push({ id: 'more', blocks: [{ type: 'panel', rows: [
    { label: 'The record', value: 'Its rule and request ids', sheet: { title: name, blocks: [
      { type: 'code', label: 'Its rule in policy.json', text: JSON.stringify(rule ?? {}, null, 2) },
      ...(rs.length ? [{ type: 'code', label: 'Its requests: id, agent, house, state', text: rs.slice(0, 40).map((r) => `${r.id}  ${r.agent}  ${r.house}  ${r.state}`).join('\n') }] : []),
    ] } },
    { label: 'Remove', value: `Houses started after this won't get ${name}.`,
      act: { action: 'remove', label: 'Remove', tone: 'danger', fields: { name }, confirm: `Bodies started after this won't get ${name}.` } },
  ] }] });
  return { title: name, intro: 'Write-only: its value is never shown.', sections };
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
  // From an agent's Secrets tab: that agent's requests and grants only.
  const scope = typeof env?.LOOM_SCOPE === 'string' && /^[a-z][a-z0-9-]{0,39}$/.test(env.LOOM_SCOPE) ? env.LOOM_SCOPE : '';
  if (scope) {
    const f = req.fields && typeof req.fields === 'object' ? req.fields : {};
    const theirs = Object.hasOwn(ANSWERS, action) ? allRequests(c).find((r) => r.id === f.id)?.agent === scope
      : action === 'stop-always' || action === 'houses' || action === 'auto' ? f.agent === scope : false;
    if (!theirs) return no(`This is ${scope}'s page.`);
  }
  if (Object.hasOwn(ANSWERS, action)) {
    const id = req.fields?.id;
    if (typeof id !== 'string' || !/^q-[0-9a-f]{8}$/.test(id)) return no('That is not a request.');
    try {
      const r = answer(c, id, action, whoOf(req));
      return { ok: true, message: action === 'always'
        ? `Allowed: ${named(r.agent)}'s ${r.secret}, and ${named(r.agent)}'s houses get it without asking from now on.`
        : `${ANSWERS[action]}: ${named(r.agent)}'s ${r.secret}${action === 'grant' ? `, for ${r.minutes} min` : ''}.`, page: '' };
    } catch (err) { return no(err.message); }
  }
  if (action === 'stop-always') {
    const { name, agent } = req.fields && typeof req.fields === 'object' ? req.fields : {};
    // The agent is checked by exact membership in the policy's list (stopAlways), not by a pattern of its own.
    if (typeof name !== 'string' || !NAME.test(name) || typeof agent !== 'string' || agent.length > 64) return no('That is not a secret and an agent.');
    try {
      stopAlways(c, name, agent, whoOf(req));
      return { ok: true, message: `${named(agent)}'s houses will ask for ${name} again.`, page: '' };
    } catch (err) { return no(err.message); }
  }
  if (action === 'houses' || action === 'auto') {
    // A panel's switch (loom docs/extensions.md, Panels): on is "on" or "", and it applies at once.
    const { name, agent, on } = req.fields && typeof req.fields === 'object' ? req.fields : {};
    if (typeof name !== 'string' || !NAME.test(name) || typeof agent !== 'string' || !/^[a-z][a-z0-9-]{0,39}$/.test(agent)) return no('That is not a secret and an agent.');
    if (!names(c).includes(name)) return no(`There is no secret named ${name}.`);
    const yes = on === 'on';
    try {
      if (action === 'houses') setHouses(c, name, agent, yes, whoOf(req));
      else setAlways(c, name, agent, yes, whoOf(req));
    } catch (err) { return no(err.message); }
    return { ok: true, page: '', message: action === 'houses'
      ? (yes ? `${named(agent)}'s houses get ${name} when they start.` : `${named(agent)}'s houses start without ${name}.`)
      : (yes ? `${named(agent)}'s houses get ${name} without asking you, 8 hours at a time.` : `${named(agent)}'s houses will ask for ${name} again.`) };
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
      ? (action === 'add' ? `${name} already exists. To change it, use Replace on ${name} on its page.`
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
  for (const name of Object.keys(secrets).sort()) record(c, { event: 'set', secret: name, how: 'restore' });
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
      if (sub === 'page') { io.stdout(JSON.stringify(uiPage(c, await readRequest(io), io.env)) + '\n'); return 0; }
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

    case 'may': {
      // Anyone at loom's machine may ask; the answer is the policy's, never a value.
      allow(['--json']);
      if (pos.length !== 2) throw new Fail('usage: loom secrets may <agent> <name> [--json]', 2);
      checkName(pos[1]);
      let r;
      try { r = may(c, pos[0], pos[1]); } catch (err) { throw new Fail(err.message, 2); }
      io.stdout(flags.has('--json') ? JSON.stringify(r) + '\n' : `${r.may}${r.why ? `: ${r.why}` : ''}\n`);
      return r.may === 'allowed' ? 0 : 1;
    }

    case 'issue': {
      // A house's secret, to the runtime starting it (agent-runtime.md, section 6): the policy decides (may), and
      // only the runtime's own process asks. loom names that process (LOOM_PIECE_NAME); nothing here reads a flag
      // that says "let me read secrets". A guardrail, not a boundary, as the gate always was (README, "Threat model").
      const args2 = args.filter((a, i) => a !== '--agent' && a !== '--house' && args[i - 1] !== '--agent' && args[i - 1] !== '--house');
      const agent = args[args.indexOf('--agent') + 1];
      const house = args.includes('--house') ? args[args.indexOf('--house') + 1] : undefined;
      if (args2.length !== 1 || !args.includes('--agent') || !agent) throw new Fail('usage: loom secrets issue <name> --agent <agent> [--house <id>]', 2);
      checkName(args2[0]);
      if (!['runtime', 'box'].includes(io.env.LOOM_PIECE_NAME ?? '')) {
        throw new Fail('refused: issue is the runtime\'s, from its own process, for a house it\'s starting. A body gets its secrets that way, or asks (request).', 4);
      }
      let r;
      try { r = may(c, agent, args2[0]); } catch (err) { throw new Fail(err.message, 2); }
      if (r.may !== 'allowed') throw new Fail(`refused: ${r.may} for ${agent}: ${r.why}`, 4);
      const data = decrypt(c, io.env);
      if (!Object.hasOwn(data, args2[0])) throw new Fail(`no secret named ${args2[0]}`, 3);
      auditIssue(c, agent, args2[0], house);
      io.stdout(data[args2[0]]);
      return 0;
    }

    case 'policy': {
      // The owner's, at loom's machine: not another piece's process, not a house.
      if ((io.env.LOOM_PIECE_NAME && io.env.LOOM_PIECE_NAME !== 'secrets') || io.env.HOUSE_ID) throw new Fail('refused: the policy is the owner\'s, at loom\'s machine', 4);
      if (pos[0] === 'houses' && pos.length === 3) {
        allow(['--off']);
        checkName(pos[1]);
        try { setHouses(c, pos[1], pos[2], !flags.has('--off')); } catch (err) { throw new Fail(err.message, 2); }
        io.stderr(`${pos[2]}'s houses ${flags.has('--off') ? 'no longer get' : 'get'} ${pos[1]} when they start\n`);
        return 0;
      }
      if (pos[0] === 'houses-import' && pos.length === 1) {
        allow([]);
        const m = await readRequest(io);
        if (!m || typeof m !== 'object' || Array.isArray(m)) throw new Fail('houses-import takes {"<agent>": ["<name>", ...]} on stdin', 2);
        let n = 0;
        for (const [agent, list] of Object.entries(m)) {
          if (!Array.isArray(list)) throw new Fail(`${agent}: a list of secret names`, 2);
          for (const name of list) { checkName(name); try { setHouses(c, name, agent, true); n++; } catch (err) { throw new Fail(`${agent} ${name}: ${err.message}`, 2); } }
        }
        io.stderr(`allowed ${n} secret${n === 1 ? '' : 's'} at house start\n`);
        return 0;
      }
      throw new Fail('usage: loom secrets policy houses <name> <agent> [--off] | policy houses-import < map', 2);
    }

    case 'state': {
      // loom's machine only (the clock parks a body on a request): its state, never a value.
      allow([]);
      if (pos.length !== 1 || !/^q-[0-9a-f]{8}$/.test(pos[0])) throw new Fail('usage: loom secrets state <request id>', 2);
      try { io.stdout(stateOf(c, pos[0]) + '\n'); } catch (err) { throw new Fail(err.message, 3); }
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
      // Read on loom's machine (a host script, or the owner at a terminal): its page says where it's used.
      record(c, { event: 'host-read', secret: pos[0], how: 'get' });
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
      record(c, { event: 'host-read', secret: pos[0], how: 'podman' });
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
