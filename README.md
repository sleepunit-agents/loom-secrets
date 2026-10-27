# loom-secrets

loom's `secrets` piece (see loom's `docs/extensions.md`): named secrets in an
encrypted store. Install it so that `loom-secrets` is on `PATH`, and then
`loom secrets …` reaches it through loom's piece dispatch. You can also run it
directly.

```bash
loom secrets init                         # age key (0600) + empty store
loom secrets add google-pass              # type the value (no echo), or pipe it in:
printf %s "$VALUE" | loom secrets add google-pass
loom secrets list                         # names only
loom secrets podman google-pass art-google-pass   # into a podman secret, unprinted
loom secrets get google-pass --reveal     # at a terminal only (see below)
loom secrets rm google-pass
```

Underneath it's [sops](https://github.com/getsops/sops) with an
[age](https://github.com/FiloSottile/age) key. The binaries (`sops`, `age-keygen`,
and `age` for the bundle verbs) must be on `PATH`, or named by
`LOOM_SECRETS_SOPS`, `LOOM_SECRETS_AGE_KEYGEN` and `LOOM_SECRETS_AGE`. The store is
`$LOOM_SECRETS_DIR/store.sops.json`, and `LOOM_SECRETS_DIR` defaults to
`~/.config/loom-secrets`. The key is `age.key` beside it, or `SOPS_AGE_KEY_FILE`.

## The contract (what any `secrets` piece must do)

Any replacement for this piece, whether it's Bitwarden, a cloud KMS, or
whatever comes next, has to keep these. `test/cli.test.mjs` checks them for
this implementation.

- **ac-sec-no-argv**: a value never travels in argv. `add <name> <value>` is
  refused with exit 2. Values come from stdin or a no-echo prompt. The piece
  hands values to its own tools on stdin, never as arguments.
- **ac-sec-at-rest**: the store on disk never holds a plaintext value.
- **ac-sec-list-blind**: `list` shows names without decrypting anything. It
  works without the key.
- **ac-sec-no-body-read**: nothing prints a value unless `get --reveal` is
  allowed, either at an interactive terminal or with `LOOM_SECRETS_ALLOW_GET=1`
  set by the host side (the selvedge). By default a body is refused with exit 4.
  A body gets its secrets injected into its runtime. It doesn't read them out
  of the store.
- **ac-sec-inject**: `podman <name> <podman-secret>` puts a value into a podman
  secret without printing it. It sits behind the same gate as `get --reveal`,
  because pointing `LOOM_SECRETS_PODMAN` at `cat` would make it a print. This
  is how a tank gets its keys: `house/tank` runs on the host side.
- **ac-sec-loom-boundary**: the piece never reads or writes loom's stores.
  Secrets are authority, not continuity.
- **ac-sec-ui-write-only**: loom's page can add, replace and remove a secret,
  and nothing more. `ui act` has no action that reads, reveals or injects a
  value; `get` and `podman` stay CLI-only behind their gate. Any other action
  name is refused.
- **ac-sec-ui-no-value-out**: no `ui` answer (manifest, page or action result)
  ever holds a value. The page lists names only, a `secret` field never
  carries a `value`, and an action's message names the secret, never the
  value. A name that fails the rules isn't echoed back either, since whatever
  was typed there might be a value.
- **ac-sec-ui-stdin-only**: on the page a value arrives only in `ui act`'s
  stdin JSON. From there it goes the same way as `add`: to sops on stdin, never
  in argv, env, a log or a file left behind. It's checked like `add`: a name
  by the CLI's rules, a value non-empty and at most 64 KB.
- **ac-sec-export-encrypted**: `bundle export` writes a part that holds no
  plaintext value (nor a name), encrypted only to the recipients in
  `LOOM_EXPORT_RECIPIENTS`. It refuses with no recipients or a malformed one,
  and never echoes a malformed one (it might be a pasted private key). It
  prints no value or key; stdout is the part and nothing else.
- **ac-sec-import-rekeys**: after `bundle import`, the store opens with this
  machine's key and not the bundle's. The owner's identity is used only to
  open the part.
- **ac-sec-import-no-clobber**: `bundle import` refuses (exit 3) over a store
  that holds secrets unless `--force`, and a part that doesn't open with
  `LOOM_IMPORT_IDENTITY` writes nothing: no key, no store.
- **ac-sec-bundle-no-disk**: on export and import the plaintext map moves
  between sops and age through the piece's memory and their stdin/stdout,
  never argv, env, a log or a file.
- **Exit codes**: 0 ok, 1 a tool failed (a part that doesn't decrypt, sops or
  age erroring), 2 usage or refused input, 3 no such secret / already exists
  (without `--force`), 4 reveal refused.

## On loom's page

The piece answers loom's page contract (v2, loom's `docs/extensions.md`, "The
page"). It gets a **Secrets** tab and a Home tile with the count and whether
the key is on this host.

```bash
loom-secrets ui --json         # manifest: tab, tile; no asks
echo '{"path":"","query":{}}' | loom-secrets ui page --json
echo '{"action":"add","path":"","fields":{"name":"x","value":"..."}}' | loom-secrets ui act --json
```

The page (`""`) has an **Add a secret** form and **In the store**, which lists
names. Each name folds open to a **Replace** form and a **Remove** button.
`ui act` takes `add` (refuses a name that exists and points to Replace),
`replace` (the name must exist) and `remove`. It answers
`{ok, message, page: ""}`. A store bigger than one page allows (160 names) is
split into parts, picked with `?part=`.

The page is **write-only**: you can put a value in, but you can't read it back
(ac-sec-ui-*). A value typed into the form goes to loom, which checks the
sign-in and anti-forgery token, and then to this piece on stdin. loom never
logs it or stores it. A multi-line value (a JSON key, an `.env`) is easier to
pipe in with `loom secrets add`.

## Requests: a house asks, the owner says yes

A house can ask for a secret it wasn't started with, say *what it's for*,
and get it for a while if the policy allows it or the owner says yes on
loom's page. A rarely needed, powerful credential (an owner's GitHub token
for one org's pushes) then lives in no house until one asks, and nobody
reads it without the owner knowing.

```
house:  piece-call secrets request onterris-gh --why "push the fix for onterris/pond#212"
loom:   POST /api/secrets/run, as the house's own token (agent:art@h-104)
piece:  policy.json says auto (granted), never (refused), or, by default, ask:
        a card on loom's Home with Allow and Deny, pushed to the owner's phone
house:  piece-call secrets get onterris-gh        (works once granted, for that house only)
```

- **Only a house asks or reads:** its token names it (loom: `agent:<a>[/<service>]@<house>`).
  A grant is that house's, for `minutes` (60 unless the policy says, 8 h at
  most). It ends with the house, since the house's token is revoked when the
  house is over.
- **The policy decides auto and never; the reason never does.** The reason a
  house gives is its own words, written by a body that may be steered, so
  it's shown to the owner and decides nothing. `policy.json` in the store's
  directory:

  ```json
  {"v":1,"default":"ask","secrets":{
    "mark-discord-token":{"grant":"auto","agents":["mark"],"minutes":480},
    "root-ssh":{"grant":"never"}}}
  ```

  `auto` is only for the agents it names. Anyone else asks. Anything unlisted
  takes `default` (`ask` unless set).
- **Asking twice is one request.** The same house and secret gets the same
  card while it's pending or granted.
- **No value is in a request, the page, the record or a log.** `requests.json`
  and `audit.jsonl` (every request, answer, read and refused read) hold names,
  houses and reasons. `get` reads the value from the store for the granted
  house, through loom's piece API.
- **The owner can revoke** a live grant from the page's Requests.

## In loom's bundle

`loom export` and `loom restore` (loom's `docs/specs/household.md`, "Export
and restore") carry this piece's part through two verbs under `bundle`:

```bash
LOOM_EXPORT_RECIPIENTS=age1…,age1… loom-secrets bundle export > secrets.part
LOOM_IMPORT_IDENTITY=~/owner.key loom-secrets bundle import [--force] < secrets.part
```

**Why the part is re-encrypted.** The store is sops-encrypted to this box's
`age.key`. If the box dies, that key goes with it. So `bundle export` decrypts
the store and encrypts it again to the owner's recipients, and `bundle import`
on a fresh machine opens it with the owner's identity and encrypts it to that
machine's own key. loom never decrypts the part.

**The part format** (`loom-secrets/1`) is an ASCII-armored age file,
`age -e -a -r <each recipient>`, over the canonical JSON of the decrypted map,
names sorted:

```json
{"format":"loom-secrets/1","secrets":{"<name>":"<value>"}}
```

No sops metadata travels, so a part opens with `age -d -i <identity>` alone.

**A part is encrypted, not signed.** age proves who can read a part, not who
made it. Anyone holding the owner's *public* recipient could build a part, so
`bundle import` trusts what it's given: only import a part from a bundle you
made yourself. It can't be signed at export time in a way that survives the
case it's for. The exporting box's key is the thing that's gone after the
apocalypse, and only the owner's public key is present when exporting.
Importing also takes a deliberate step: running it with the owner's private
identity in hand.
Recipients are `age1…` keys (X25519 or a plugin's, such as a YubiKey) or ssh
public keys, comma-separated.

- **`bundle export`** with no store writes a valid empty part
  (`"secrets":{}`), so a restore lays down an empty store too. It creates
  nothing on disk.
- **`bundle import`** checks that `LOOM_IMPORT_IDENTITY` names a file,
  decrypts and checks the part (format, names by the CLI's rules, non-empty
  string values), and only then writes. If there's no key it makes one, the
  same way `init` does (a 0700 dir, a 0600 key). It refuses over a store that
  holds any secret unless `--force`; an empty store from `init` is fine.
  `--force` replaces the whole store with the part, and keeps this machine's
  key.
- Any other `bundle <x>` is exit 2.

## Threat model: the gate is a guardrail, the key is the boundary

The `get`/`podman` gate (a terminal, or `LOOM_SECRETS_ALLOW_GET=1`) stops a
body from printing a secret *by asking this CLI*. It **doesn't** stop a process
that runs as the same user and can read the age key: that process can run
`sops --decrypt` itself. Treat the gate as protection against careless or
casual reads. It's not a security boundary.

The boundary is **who can read `age.key`**:

- **In a tank: covered.** The key never enters a tank. A body gets only the
  secrets the host injected, and nothing can read them out of a store.
- **On a shared host, where bodies run as the store's user: not covered.**
  That's no worse than plaintext key files, and better at rest and in backups.
  The step that would cover it: keep the key under a separate user or a
  host broker, so bodies have to go through a request the selvedge (or the
  approval piece) answers.

### The bundle verbs

`bundle export` isn't behind the `get` gate: loom runs it with no terminal and
only `LOOM_EXPORT_RECIPIENTS` set. So a same-user process that can run this
CLI can export the store to a recipient of its own and read it. That's the
same reach it already has through `sops --decrypt` with the key, so it doesn't
move the boundary, but it does skip the guardrail. In a tank nothing changes,
because the key never enters one. `bundle import` is a writer, like the page:
it can replace the store (with `--force`), not read it.

### The page

The page adds a writer, not a reader. Whoever is signed in to loom's page can
**add, replace or remove** a secret. Because of that, the page is worth
guarding the way the host is. A replace or remove can break a body's
credentials. It can't leak them, though. The page has no way to read a value,
so a stolen session, a forged form or a script on the page gets nothing out of
the store. (loom renders data, never a piece's markup, and the page runs no
script.) The value in a form crosses loom-http, which passes it on stdin
without logging or keeping it. That makes loom-http's process a place the
value passes through, like the terminal you'd type it into.

## Not yet

- Several recipients on the store itself (a host key plus a recovery key) and
  key rotation. The bundle part (above) is a recovery copy to the owner's key,
  but only as fresh as the last `loom export`.
- An `exec`-style injection into a process's environment. That's left out on
  purpose: env is where the first tank turn leaked a token.
- A seam to the approval piece, for "a body asks for a secret, a human says
  yes". That plus a separate-user key is what would make the gate a real
  boundary on a shared host.
