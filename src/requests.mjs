// Secret requests: a house asks for a secret it doesn't carry, and gets it if
// the policy says so or the owner says yes on the page (README, "Requests").
//
// Nothing here holds a value. The store stays the one place values live; a
// grant says "this house may read this secret until then", and `get` reads it
// from the store for the house that holds the grant, and only that one. A
// house's token names its house (loom: agent:<a>[/<service>]@<house>), so a
// grant is one house's and ends with it: the house token is revoked when the
// house is over, and every grant has its own expiry too.
//
//   policy.json   {"v":1,"default":"ask","secrets":{"NAME":{"grant":"auto"|"ask"|"never","agents":["art"],"minutes":60}}}
//   requests.json every request: pending, granted, denied, revoked (no values)
//   audit.jsonl   one line a request, decision and read
//
// The reason a house gives is its own words: shown to the owner, never what
// decides. auto and never come from the policy alone.
import { appendFileSync, closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';

const LEVELS = new Set(['auto', 'ask', 'never']);
const MAX_MINUTES = 8 * 60;
const DEFAULT_MINUTES = 60;
const WHY_MAX = 300;
const HOUSE = /^h-[0-9]{1,9}$/;
const KEEP = 200;            // decided requests kept for the page and the record

export class RequestError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

const paths = (c) => ({ policy: join(c.dir, 'policy.json'), requests: join(c.dir, 'requests.json'), audit: join(c.dir, 'audit.jsonl'), lock: join(c.dir, 'requests.lock') });

/** One line, nothing that could pass for markup: what a house says, shown as its words. */
export function plain(text, n = WHY_MAX) {
  const t = String(text ?? '').normalize('NFKC').replace(/[\p{C}\p{Z}<>[\]{}]/gu, (ch) => (ch === ' ' ? ' ' : ' '));
  return t.replace(/ +/g, ' ').trim().slice(0, n);
}

export function readPolicy(c) {
  const p = paths(c).policy;
  let d = {};
  try { d = JSON.parse(readFileSync(p, 'utf-8')); } catch { d = {}; }
  const secrets = d && typeof d.secrets === 'object' && !Array.isArray(d.secrets) ? d.secrets : {};
  return { default: LEVELS.has(d?.default) ? d.default : 'ask', secrets };
}

/** What the policy says for this agent and secret: auto, ask or never, and for how long. */
export function decide(policy, agent, secret) {
  const rule = policy.secrets[secret];
  const minutes = Math.min(MAX_MINUTES, Number.isInteger(rule?.minutes) && rule.minutes > 0 ? rule.minutes : DEFAULT_MINUTES);
  if (!rule || !LEVELS.has(rule.grant)) return { level: policy.default, minutes };
  if (rule.grant === 'never') return { level: 'never', minutes };
  // auto is for the agents it names; anyone else asks.
  if (rule.grant === 'auto') return { level: Array.isArray(rule.agents) && rule.agents.includes(agent) ? 'auto' : 'ask', minutes };
  return { level: 'ask', minutes };
}

function load(c) {
  try {
    const d = JSON.parse(readFileSync(paths(c).requests, 'utf-8'));
    if (d && d.v === 1 && d.requests && typeof d.requests === 'object') return d;
  } catch { /* none yet */ }
  return { v: 1, requests: {} };
}

function save(c, d) {
  // The newest decided ones are kept; pending and live grants always.
  const all = Object.values(d.requests).sort((a, b) => (b.at > a.at ? 1 : -1));
  const now = Date.now();
  const keep = new Set(all.filter((r) => r.state === 'pending' || (r.state === 'granted' && Date.parse(r.expires) > now)).map((r) => r.id));
  for (const r of all) { if (keep.size >= KEEP) break; keep.add(r.id); }
  d.requests = Object.fromEntries(all.filter((r) => keep.has(r.id)).map((r) => [r.id, r]));
  const p = paths(c).requests;
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(d, null, 2) + '\n', { mode: 0o600 });
  renameSync(tmp, p);
}

function locked(c, fn) {
  const { lock } = paths(c);
  let fd;
  for (let i = 0; ; i++) {
    try { fd = openSync(lock, 'wx', 0o600); break; } catch {
      if (i > 50) throw new RequestError('the requests are busy; try again shortly', 503);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
  try { return fn(); } finally { closeSync(fd); rmSync(lock, { force: true }); }
}

function audit(c, event) {
  appendFileSync(paths(c).audit, JSON.stringify({ at: new Date().toISOString(), ...event }) + '\n', { mode: 0o600 });
}

const live = (r, now = Date.now()) => r.state === 'granted' && Date.parse(r.expires) > now;
const view = (r) => ({ id: r.id, secret: r.secret, agent: r.agent, house: r.house, state: live(r) ? 'granted' : r.state === 'granted' ? 'expired' : r.state, why: r.why, minutes: r.minutes, at: r.at, ...(r.expires ? { expires: r.expires } : {}) });

/** The house a caller is: only a house's own token (agent, with its house) asks or reads. */
function houseOf(caller) {
  if (!caller || caller.kind !== 'agent' || typeof caller.agent !== 'string' || !HOUSE.test(caller.house ?? '')) {
    throw new RequestError('only a house asks for a secret: its own token names it (agent:<a>@<house>)', 403);
  }
  return { agent: caller.agent, house: caller.house, service: typeof caller.service === 'string' ? caller.service : undefined };
}

/** A house asks. Returns its request: granted (by the policy), pending (the owner's call) or denied. */
export function request(c, caller, { secret, why, minutes }, known) {
  const h = houseOf(caller);
  if (!known.includes(secret)) throw new RequestError(`there is no secret named ${secret}`, 404);
  const reason = plain(why);
  if (!reason) throw new RequestError('say what it\'s for (--why): the owner sees it when it asks them');
  const policy = readPolicy(c);
  const d0 = decide(policy, h.agent, secret);
  const want = Number.isInteger(minutes) && minutes > 0 ? Math.min(minutes, d0.minutes) : d0.minutes;
  return locked(c, () => {
    const d = load(c);
    // Asking again gets the same request: one card on the page, not one an ask.
    const same = Object.values(d.requests).find((r) => r.house === h.house && r.secret === secret && (r.state === 'pending' || live(r)));
    if (same) return view(same);
    const r = { id: 'q-' + randomBytes(4).toString('hex'), secret, agent: h.agent, house: h.house, ...(h.service ? { service: h.service } : {}),
      why: reason, minutes: want, at: new Date().toISOString(), state: 'pending' };
    if (d0.level === 'never') { r.state = 'denied'; r.by = 'policy'; r.decided = r.at; }
    if (d0.level === 'auto') { r.state = 'granted'; r.by = 'policy'; r.decided = r.at; r.expires = new Date(Date.now() + want * 60_000).toISOString(); }
    d.requests[r.id] = r;
    save(c, d);
    audit(c, { event: 'request', id: r.id, secret, agent: h.agent, house: h.house, why: reason, result: r.state, by: r.by ?? null });
    return view(r);
  });
}

/** Whether this house may read this secret now. Throws (403) if not, saying why. */
export function mayRead(c, caller, secret) {
  const h = houseOf(caller);
  const d = load(c);
  const mine = Object.values(d.requests).filter((r) => r.house === h.house && r.secret === secret);
  const ok = mine.find((r) => live(r));
  if (ok) { audit(c, { event: 'read', id: ok.id, secret, agent: h.agent, house: h.house }); return ok; }
  const pending = mine.find((r) => r.state === 'pending');
  audit(c, { event: 'refused-read', secret, agent: h.agent, house: h.house });
  throw new RequestError(pending
    ? `${secret} is waiting on the owner (request ${pending.id}); try again once they've answered`
    : `this house has no grant for ${secret}: ask for it first (request ${secret} --why "…")`, 403);
}

/** This house's requests, newest first (no values). */
export function mine(c, caller) {
  const h = houseOf(caller);
  return Object.values(load(c).requests).filter((r) => r.house === h.house).sort((a, b) => (b.at > a.at ? 1 : -1)).map(view);
}

export function all(c) {
  return Object.values(load(c).requests).sort((a, b) => (b.at > a.at ? 1 : -1)).map(view);
}

/** The owner answers a request (the page): grant, deny, or revoke a live grant. */
export function answer(c, id, action) {
  return locked(c, () => {
    const d = load(c);
    const r = d.requests[id];
    if (!r) throw new RequestError('there is no such request', 404);
    const now = new Date();
    if (action === 'grant' || action === 'deny') {
      if (r.state !== 'pending') throw new RequestError(`that request is already ${view(r).state}`, 409);
      r.state = action === 'grant' ? 'granted' : 'denied';
      r.by = 'owner';
      r.decided = now.toISOString();
      if (action === 'grant') r.expires = new Date(now.getTime() + r.minutes * 60_000).toISOString();
    } else if (action === 'revoke') {
      if (!live(r)) throw new RequestError('that grant isn\'t live', 409);
      r.state = 'revoked';
      r.decided = now.toISOString();
    } else throw new RequestError('no such answer');
    save(c, d);
    audit(c, { event: action, id, secret: r.secret, agent: r.agent, house: r.house, by: 'owner' });
    return view(r);
  });
}
