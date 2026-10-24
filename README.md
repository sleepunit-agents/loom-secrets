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
[age](https://github.com/FiloSottile/age) key. Both binaries must be on `PATH`, or
named by `LOOM_SECRETS_SOPS` and `LOOM_SECRETS_AGE_KEYGEN`. The store is
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
- **Exit codes**: 0 ok, 2 usage or refused input, 3 no such secret / already
  exists (without `--force`), 4 reveal refused.

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

## Not yet

- Several recipients (a host key plus a recovery key) and key rotation.
- An `exec`-style injection into a process's environment. That's left out on
  purpose: env is where the first tank turn leaked a token.
- A seam to the approval piece, for "a body asks for a secret, a human says
  yes". That plus a separate-user key is what would make the gate a real
  boundary on a shared host.
