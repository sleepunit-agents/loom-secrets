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
//   - it never touches loom's stores
import { spawnSync } from 'node:child_process';
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { join } from 'node:path';

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
  ui --json                     The section for loom's page (a count, no names)

Values are never taken from argv. Store: $LOOM_SECRETS_DIR (default
~/.config/loom-secrets), sops + age. Binaries: $LOOM_SECRETS_SOPS (default
sops), $LOOM_SECRETS_AGE_KEYGEN (default age-keygen), $LOOM_SECRETS_PODMAN
(default podman).
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
      withLock(c, () => {
        const data = decrypt(c, io.env);
        if (pos[0] in data && !flags.has('--force')) throw new Fail(`${pos[0]} already exists (pass --force to replace it)`, 3);
        data[pos[0]] = value;
        encrypt(c, io.env, data);
      });
      io.stderr(`stored ${pos[0]}\n`);
      return 0;
    }

    case 'ui': {
      // The secrets piece's section on loom's page (loom docs/extensions.md,
      // "UI sections"). A count and where the store lives: never a name or a value.
      allow(['--json']);
      const n = names(c);
      const keyed = existsSync(c.key);
      io.stdout(JSON.stringify({ sections: [{ id: 'store', title: 'Secrets', blocks: [
        { type: 'stats', items: [
          { label: 'secrets', value: String(n.length) },
          { label: 'key', value: keyed ? 'on this host' : 'missing', tone: keyed ? 'ok' : 'bad' },
        ] },
        { type: 'text', text: 'sops + age, encrypted at rest. Bodies get secrets injected, never read from here.' },
      ] }] }) + '\n');
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
      withLock(c, () => {
        const data = decrypt(c, io.env);
        if (!(pos[0] in data)) throw new Fail(`no secret named ${pos[0]}`, 3);
        delete data[pos[0]];
        encrypt(c, io.env, data);
      });
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
      if (!(pos[0] in data)) throw new Fail(`no secret named ${pos[0]}`, 3);
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
      if (!(pos[0] in data)) throw new Fail(`no secret named ${pos[0]}`, 3);
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
