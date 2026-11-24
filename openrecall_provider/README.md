# openrecall memory provider for Hermes Agent

Standalone memory backend for [Hermes Agent](https://hermes-agent.nousresearch.com/)
that talks to a self-hosted [openrecall](https://github.com/Twigpine/openrecall) server
(the project was `openrecall` before the 2026 rename; this provider still
decrypts the legacy salt so existing entries keep working)
with **client-side AES-256-GCM encryption**. The server only ever sees
ciphertext — your passphrase never leaves this machine.

This is the Python sibling to the upstream Bun/TS `client/crypto.ts`. Any
entry written by either client round-trips through the other. Five tools
(`openrecall_save`, `openrecall_recall`, `openrecall_search`, `openrecall_list`,
`openrecall_delete`) are exposed to the agent.

## Install

```bash
pip install hermes-openrecall-provider
```

The package registers a `hermes_agent.memory_providers` entry point so
`hermes memory setup` lists "openrecall" alongside Honcho, OpenViking, Mem0,
Hindsight, and the other built-in providers.

## One-time setup

```bash
# 1. Provide the passphrase. Preferred: a profile-scoped secret, so one
#    Hermes process serving several profiles cannot read another's passphrase.
hermes config set OPENRECALL_PASSPHRASE "$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"

# 2. Point Hermes at this provider and run the setup wizard
hermes config set memory.provider openrecall
hermes memory setup
```

The wizard prompts for the server URL and namespace; the API key goes to
`.env`, and the passphrase is read at runtime through Hermes' profile secret
scope (or an explicit file, below) and never persisted to config.

A passphrase file is opt-in only: set `memory.openrecall.passphrase_file` to
the path you want read. There is no default location — a fixed path is
readable by every profile on the host.

At runtime the provider reads the `memory.openrecall.{url,namespace}` block from
the active Hermes config (profile-aware). Precedence: constructor config >
`OPENRECALL_NAMESPACE` env > config.yaml > built-in defaults — so
`OPENRECALL_NAMESPACE=... hermes openrecall get <key>` still works as a manual
cross-namespace escape hatch.

## Direct CLI

Once `memory.provider = openrecall` is active, the subcommand shows up:

```bash
hermes openrecall status              # config + server liveness
hermes openrecall list                # all stored entry keys
hermes openrecall get <key>           # decrypt and print one entry
hermes openrecall save <key> <value>  # write (or pipe via stdin)
hermes openrecall search <query>      # literal substring search
hermes openrecall delete <key>
hermes openrecall config              # show the memory.openrecall block
```

## Encryption reference

The crypto matches `client/crypto.ts` byte-for-byte:

| Step | Algorithm |
|---|---|
| KDF | `scrypt(passphrase, salt=sha256("memlawb:"+ns), N=32768, r=8, p=1, dklen=32)` |
| Cipher | `AES-256-GCM`, AAD = entry key |
| Nonce | `HMAC-SHA256(key, entryKey \|\| 0x00 \|\| pt)[:12]` (deterministic) |
| Layout | `[0x01 version][12-byte nonce][16-byte tag][ct]`, base64 |

Deterministic nonces are deliberate: they let the server do delta sync
by ciphertext hash without ever seeing plaintext. The only thing this
leaks is "two entries are byte-identical" — acceptable for memory.

## Wire protocol

```
GET    /health                    -> { ok, store, service }
GET    /api/memory/:ns            -> { content: { entries: {k: b64ct} } }
PUT    /api/memory/:ns            -> { entries: { k: b64ct } } (delta upsert)
DELETE /api/memory/:ns?key=K      -> removes the entry
```

## Hooks implemented

All optional hooks the bundled providers (Honcho, MemPalace) implement:

- `prefetch(query)` — recall relevant entries before each turn
- `sync_turn(user, asst)` — no-op by design; the model is responsible
  for calling `openrecall_save` on durable facts
- `on_turn_start`, `on_session_end` — no-op
- `on_pre_compress` — returns `""` (nothing to add)
- `on_memory_write(action, target, content, metadata)` — mirrors
  built-in `memory` tool writes to `hermes/<target>/<path>` keys
- `backup_paths()` — passphrase file(s) so `hermes backup` includes them

## Why this exists

Hermes ships with cloud-first (Honcho, Mem0, Hindsight, RetainDB) and
local (Holographic, MemPalace, ByteRover) memory providers, but **no
zero-knowledge option**. openrecall is the only one in the ecosystem that
guarantees the server can never read your memory. This provider fills
that gap for Hermes specifically.

## Related

- Upstream server + TS client: <https://github.com/Twigpine/openrecall> (`@twigpine/openrecall`)
- Hermes memory provider plugin guide:
  <https://hermes-agent.nousresearch.com/docs/developer-guide/memory-provider-plugin>
- Standalone-provider contract (PR #82649):
  <https://github.com/NousResearch/hermes-agent/pull/82649>
