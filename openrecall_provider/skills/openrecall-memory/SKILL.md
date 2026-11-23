---
name: openrecall-memory
description: Provider-scoped maintenance for the openrecall memory backend. Use when the user reports a openrecall-specific issue (server unreachable, passphrase missing, namespace collision, decrypt failures) — NOT for general memory use, which is covered by the bundle-level openrecall-memory skill in skills/.
---

# openrecall provider maintenance

This skill is **provider-scoped** — it loads only when `memory.provider = openrecall`
is active. For general openrecall usage (recall, save, list, search, delete) see the
bundle-level `skills/openrecall-memory/SKILL.md` which uses the same tool names.

## When to use

- Server is unreachable (timeout, DNS, connection refused)
- Passphrase is missing or wrong (decrypt fails with `ValueError` or
  `Unsupported state or unable to authenticate data`)
- Namespace collision or clobber between profiles
- `hermes openrecall status` exits non-zero
- User wants to rotate the passphrase, change the server, or move to
  a different namespace

## Diagnostic commands

```bash
hermes openrecall status              # config + server liveness + entry count
hermes openrecall config              # raw memory.openrecall block from config.yaml
hermes openrecall list                # all stored entry keys
hermes openrecall get <key>           # decrypt and print one entry
```

## Common fixes

- **Passphrase missing**: create `~/.openrecall-passphrase.txt` (chmod 600) or
  export `OPENRECALL_PASSPHRASE`. Re-run `hermes openrecall status`.
- **Server unreachable**: confirm `memory.openrecall.url` in config.yaml points
  at a live openrecall server (`curl <url>/health` should return
  `{"ok":true,...}`). The plugin default is the documented live cluster
  address; override for self-hosted.
- **Healthy from localhost but timeouts from other machines**: check
  network policy and firewall rules between the client and the store. If
  the store runs in Kubernetes, a NetworkPolicy may need a rule for pod
  and node traffic; a curl from the server host bypasses policy, so a
  local success alone does not prove remote reachability.
- **Decrypt fails**: passphrase is wrong OR the entry was written with a
  different namespace. Check `hermes openrecall config` for the active
  namespace; use `OPENRECALL_NAMESPACE=... hermes openrecall get <key>` to
  try a different namespace.
- **Old MCP config still present**: the separate `mcp__memlawb__*` tool
  handle is removed as of 2026-08-26. Remove `mcp_servers.openrecall` from
  `config.yaml` if it's still there.
