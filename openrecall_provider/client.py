"""openrecall HTTP + crypto client.

Extracted from the original ``__init__.py`` so the MemoryProvider, the
``hermes openrecall`` CLI subcommand, and the ``hermes memory setup`` wizard
all share the same wire protocol and encryption path. Pure-stdlib except
for ``cryptography`` (AES-256-GCM).

Wire protocol (matches the upstream ``Twigpine/openrecall`` server):

  GET    /health                   -> { ok: bool, store, service }
  GET    /api/memory/:ns           -> { ..., content: { entries: {k: b64ct} } }
  PUT    /api/memory/:ns           -> { entries: { k: b64ct } } (delta upsert)
  DELETE /api/memory/:ns?key=K     -> removes the entry from the namespace

Encryption (matches ``client/crypto.ts`` byte-for-byte):

  KDF   scrypt(passphrase, salt=sha256('<prefix>'+ns), N=1<<15, r=8, p=1, dklen=32)
        prefix is 'openrecall:' for new writes; 'memlawb:' still decrypts legacy entries
  CIPH  AES-256-GCM, AAD = entryKey, nonce = HMAC-SHA256(key, entryKey||0x00||pt)[:12]
  LAY   [0x01 version][12-byte nonce][16-byte tag][ciphertext], base64
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False

logger = logging.getLogger(__name__)

# Defaults used when the provider / CLI is invoked without explicit config.
# No host is baked in: deployments and profiles supply the address via
# ``OPENRECALL_URL`` / ``memory.openrecall.url``, and localhost is only the fallback for
# a client running on the same machine as the server.
DEFAULT_URL = os.environ.get("OPENRECALL_URL") or "http://127.0.0.1:8080"

# Namespaces and entry names travel to the server in the clear. A fixed
# ``user:default`` let two Hermes profiles on one server list and delete each
# other's entries. The default is therefore profile-specific; a user who sets
# a namespace explicitly can still share one on purpose. See
# ``_default_namespace()`` and tek's 2026-11-26 review on hermes-agent#159248.
DEFAULT_NAMESPACE = "user:default"  # fallback only when Hermes isn't importable


def _active_profile_name() -> str:
    """Best-effort active profile name, mirroring Hermes' own helper.

    A named profile's HERMES_HOME is ``~/.hermes/profiles/<name>``; the default
    root (``~/.hermes`` or an unset override) returns "" so the fallback keeps
    working. Uses ``get_hermes_home()`` when Hermes is importable, else env.
    """
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        home = get_hermes_home()
        if home is not None:
            resolved = Path(str(home))
            if resolved.parent.name == "profiles" and resolved.name:
                return resolved.name
    except Exception:
        pass
    for env_name in ("HERMES_PROFILE_NAME", "HERMES_PROFILE"):
        value = os.environ.get(env_name, "").strip()
        if value and value != "default":
            return value
    return ""


def _default_namespace() -> str:
    """Profile-specific default namespace: ``agent:<profile>`` per profile."""
    profile = _active_profile_name()
    return f"agent:{profile}" if profile else DEFAULT_NAMESPACE

#: Env var holding the passphrase. Read through Hermes' profile secret scope
#: (``agent.secret_scope.get_secret``) when Hermes is importable, so a
#: multiplexed process resolves the *active* profile's value rather than the
#: launch profile's ``os.environ`` copy.
PASSPHRASE_ENV = "OPENRECALL_PASSPHRASE"

#: Config key naming an explicit passphrase file. Empty/absent = no file is
#: read at all. Fixed probe locations are deliberately not supported: one file
#: readable by every profile on the host defeats per-profile isolation.
PASSPHRASE_FILE_CONFIG_KEY = "passphrase_file"

VERSION = 0x01
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
SCRYPT_N = 1 << 15  # 32768 — strong, ~tens of ms
SCRYPT_MAXMEM = 64 * 1024 * 1024


def _origin(url: str) -> Tuple[str, int]:
    """Return ``(host, effective_port)`` for redirect comparison."""
    parts = urllib.parse.urlsplit(url)
    scheme = (parts.scheme or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return ((parts.hostname or "").lower(), port)


class _SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow same-origin redirects only.

    ``urllib`` re-sends request headers on redirect — including
    ``Authorization``. Following a redirect to another host would hand the
    bearer token to that host, so cross-origin hops are refused outright, as
    is an https -> http downgrade on the same origin.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        old = urllib.parse.urlsplit(req.full_url)
        new = urllib.parse.urlsplit(newurl)
        if (old.hostname or "").lower() != (new.hostname or "").lower():
            raise OpenRecallError(
                f"refusing cross-origin redirect {req.full_url} -> {newurl}: "
                "the Authorization header would be forwarded to another host"
            )
        if old.scheme == "https" and new.scheme != "https":
            raise OpenRecallError(
                f"refusing https downgrade redirect {req.full_url} -> {newurl}"
            )
        if _origin(req.full_url) != _origin(newurl):
            raise OpenRecallError(
                f"refusing cross-origin redirect {req.full_url} -> {newurl}: "
                "port changed on the same host"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class OpenRecallError(RuntimeError):
    """Raised for client-side errors (missing passphrase, malformed ciphertext)."""


# --- local relevance ranking (ported from upstream src/mcp/relevance.ts) ----
# Recall is client-side by design — the server holds only ciphertext and
# cannot rank for us. Tokenize the query, score each decrypted entry, rank.
# Key matches count 2x, frontmatter-description matches 3x, body hits scale
# with log term frequency; an entry must cover >=1 query term to qualify and
# the score is scaled by the fraction of query terms covered.

_RE_TOKEN = re.compile(r"[a-z0-9]+")

_STOPWORDS = frozenset((
    "the", "a", "an", "and", "or", "to", "of", "in", "is", "it", "for",
    "on", "with", "that", "this", "i", "you", "my", "your", "we", "our",
    "as", "at", "be", "are", "was", "were", "do", "does", "what", "how",
    "when", "which", "their", "them", "they", "me",
))


def _tokenize(text: str) -> List[str]:
    return [t for t in _RE_TOKEN.findall(text.lower())
            if len(t) > 1 and t not in _STOPWORDS]


def _frontmatter_description(content: str) -> str:
    m = re.match(r"^---\r?\n([\s\S]*?)\r?\n---", content)
    if not m:
        return ""
    d = re.search(r"description:\s*(.+)", m.group(1), re.IGNORECASE)
    return d.group(1) if d else ""


def _rank_entries(query_lower: str,
                  entries: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Rank ``[(key, plaintext), ...]`` against ``query_lower`` (already lowercase)."""
    q_terms = set(_tokenize(query_lower))
    if not q_terms:
        return entries  # e.g. punctuation-only query — keep legacy behavior
    scored: List[Tuple[float, str]] = []
    for k, pt in entries:
        pt_lower = pt.lower()
        key_tokens = set(_tokenize(k))
        desc_tokens = set(_tokenize(_frontmatter_description(pt)))
        body_tf: Dict[str, int] = {}
        for t in _tokenize(pt):
            body_tf[t] = body_tf.get(t, 0) + 1

        score = 0.0
        covered = 0
        for t in q_terms:
            hit = False
            tf = body_tf.get(t)
            if tf:
                score += 1 + math.log(tf)
                hit = True
            if t in desc_tokens:
                score += 3
                hit = True
            if t in key_tokens:
                score += 2
                hit = True
            if hit:
                covered += 1
        if covered == 0:
            continue
        # Exact whole-query phrase hit is the strongest signal.
        if query_lower in pt_lower or query_lower in k.lower():
            score += 5
        # Reward entries covering more of the query; penalize one-term flukes.
        scored.append((score * covered / len(q_terms), k))
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    # Return ONLY entries that matched at least one term — never pad with
    # the unmatched rest of the corpus (that made empty-match queries
    # return everything, in arbitrary order).
    by_key = dict(entries)
    return [(k, by_key[k]) for _, k in scored]


def is_crypto_available() -> bool:
    """Return True if the ``cryptography`` package is importable."""
    return _HAS_CRYPTO


# The rename must not reach these two literals: they are key-derivation inputs, not
# names. Upstream v0.2.0 switched the prefix and states plainly that entries written
# under the old one cannot be decrypted, so the old prefix stays readable here until
# every entry has been re-encrypted by ``migrate_salt()``.
SALT_PREFIX = "openrecall:"
LEGACY_SALT_PREFIX = "memlawb:"


def _derive_key(passphrase: str, namespace: str, prefix: str = SALT_PREFIX) -> bytes:
    """Derive the 32-byte namespace key from the passphrase and a salt prefix."""
    if not passphrase:
        raise OpenRecallError("openrecall passphrase is required (set OPENRECALL_PASSPHRASE or "
                           "set OPENRECALL_PASSPHRASE or memory.openrecall.passphrase_file)")
    salt = hashlib.sha256(f"{prefix}{namespace}".encode("utf-8")).digest()
    return hashlib.scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=8,
        p=1,
        dklen=KEY_LEN,
        maxmem=SCRYPT_MAXMEM,
    )


def encrypt_entry(key: bytes, entry_key: str, plaintext: str) -> str:
    """Encrypt one entry -> base64 ciphertext blob (AES-256-GCM)."""
    if not _HAS_CRYPTO:
        raise OpenRecallError("cryptography package required for openrecall client-side "
                           "encryption (pip install cryptography)")
    pt = plaintext.encode("utf-8")
    nonce = hmac.new(key, entry_key.encode("utf-8") + b"\x00" + pt, hashlib.sha256).digest()[:NONCE_LEN]
    aes = AESGCM(key)
    ct_tag = aes.encrypt(nonce, pt, entry_key.encode("utf-8"))
    tag, body = ct_tag[:TAG_LEN], ct_tag[TAG_LEN:]
    return base64.b64encode(bytes([VERSION]) + nonce + tag + body).decode("ascii")


def decrypt_entry(key: bytes, entry_key: str, b64: str) -> str:
    """Decrypt a base64 ciphertext blob -> plaintext. Raises on tamper / wrong key."""
    if not _HAS_CRYPTO:
        raise OpenRecallError("cryptography package required for openrecall decryption")
    blob = base64.b64decode(b64)
    if len(blob) < 1 + NONCE_LEN + TAG_LEN:
        raise ValueError("ciphertext too short")
    if blob[0] != VERSION:
        raise ValueError(f"unsupported ciphertext version {blob[0]}")
    nonce, tag, body = blob[1:1 + NONCE_LEN], blob[1 + NONCE_LEN:1 + NONCE_LEN + TAG_LEN], blob[1 + NONCE_LEN + TAG_LEN:]
    return AESGCM(key).decrypt(nonce, tag + body, entry_key.encode("utf-8")).decode("utf-8")


class OpenRecallClient:
    """openrecall HTTP client with built-in client-side encryption.

    The constructor takes a URL, namespace, optional API key, and a passphrase
    source (string or None to defer to the env / file fallback chain via
    :func:`read_passphrase`). A ``OpenRecallClient`` is safe to share across
    threads for read operations; PUT/DELETE mutate server state and should
    be serialized per-namespace.
    """

    def __init__(
        self,
        url: str = DEFAULT_URL,
        namespace: str = DEFAULT_NAMESPACE,
        passphrase: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.url = url.rstrip("/")
        self.namespace = namespace
        self.api_key = api_key or None
        self.timeout = timeout
        # Derived keys, per salt prefix — invalidated on passphrase change.
        # scrypt costs tens of ms per derivation, and recall() asks for a key
        # once per entry, so deriving inside _candidate_keys() made a 269-entry
        # namespace take ~48s to read (2 derivations x 269 entries) and blow
        # every caller's timeout.
        self._passphrase = passphrase or read_passphrase()
        self._keys: Dict[str, bytes] = {}

    # -- Passphrase handling -------------------------------------------------

    @staticmethod
    def from_config(config: Dict[str, Any]) -> "OpenRecallClient":
        """Build a client from a config dict (the ``memory.openrecall`` block)."""
        return OpenRecallClient(
            url=config.get("url") or DEFAULT_URL,
            namespace=config.get("namespace") or DEFAULT_NAMESPACE,
            api_key=config.get("api_key"),
            passphrase=config.get("passphrase"),
        )

    def _key_for(self, prefix: str) -> bytes:
        """Return the memoized namespace key for ``prefix``, deriving it once."""
        key = self._keys.get(prefix)
        if key is None:
            key = _derive_key(self._passphrase, self.namespace, prefix)
            self._keys[prefix] = key
        return key

    def _candidate_keys(self) -> List[Tuple[str, bytes]]:
        """``(salt prefix, key)`` pairs to try when reading: current first, legacy second."""
        pairs: List[Tuple[str, bytes]] = []
        for prefix in (SALT_PREFIX, LEGACY_SALT_PREFIX):
            try:
                pairs.append((prefix, self._key_for(prefix)))
            except Exception:  # pragma: no cover - passphrase problems surface earlier
                continue
        return pairs

    def decrypt_any(self, entry_key: str, b64: str) -> Tuple[str, str]:
        """Decrypt with either salt. Returns ``(plaintext, salt_prefix_used)``."""
        last: Optional[Exception] = None
        for prefix, key in self._candidate_keys():
            try:
                return decrypt_entry(key, entry_key, b64), prefix
            except Exception as e:  # wrong salt and tampering are indistinguishable here
                last = e
        raise last or ValueError("no key available")

    def _get_key(self) -> bytes:
        return self._key_for(SALT_PREFIX)

    def rotate_passphrase(self, new_passphrase: str) -> None:
        """Update the passphrase and invalidate the derived key cache.

        NOTE: this only changes in-memory key derivation. It does NOT
        re-encrypt stored entries. Use ``rekey_namespace`` for a real rotation.
        """
        self._passphrase = new_passphrase
        self._keys.clear()

    # -- Backup / restore / rekey --------------------------------------------

    def export_backup(self) -> Dict[str, Any]:
        """Export the namespace as ciphertext plus metadata. No plaintext.

        The output is safe to store anywhere: the server already holds this
        ciphertext, and the passphrase needed to decrypt it is NOT included.
        Keep the passphrase backup separate (``backup_paths()`` covers it).
        """
        entries = self.get_namespace()
        return {
            "format": "openrecall-backup",
            "version": 1,
            "namespace": self.namespace,
            "url": self.url,
            "salt_prefix": SALT_PREFIX,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "entries": dict(entries),
        }

    def verify_entries(self) -> Dict[str, Any]:
        """Decrypt every entry with any supported salt, report failures."""
        entries = self.get_namespace()
        failed: List[str] = []
        salts: Dict[str, int] = {}
        for key, b64 in entries.items():
            try:
                _pt, prefix = self.decrypt_any(key, b64)
                salts[prefix] = salts.get(prefix, 0) + 1
            except Exception as e:
                logger.debug("verify failed for %s: %s", key, e)
                failed.append(key)
        return {
            "namespace": self.namespace,
            "total": len(entries),
            "decrypted": len(entries) - len(failed),
            "failed": len(failed),
            "failed_keys": failed,
            "salt_prefixes": salts,
        }

    def restore_backup(self, backup: Dict[str, Any], *, namespace: Optional[str] = None) -> Dict[str, Any]:
        """Restore entries from an export, re-encrypting for the target namespace.

        The KDF binds ciphertext to its namespace, so copying blobs verbatim
        into a different namespace would produce undecryptable entries. When
        the target differs, decrypt each entry under the source namespace key
        and re-encrypt it under the target key. The passphrase is required for
        a cross-namespace restore; a same-namespace restore needs no passphrase.
        """
        if backup.get("format") != "openrecall-backup":
            raise OpenRecallError("not an openrecall backup file")
        if backup.get("version") != 1:
            raise OpenRecallError(f"unsupported backup version: {backup.get('version')!r}")
        entries = backup.get("entries")
        if not isinstance(entries, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in entries.items()
        ):
            raise OpenRecallError("backup entries must be a {key: ciphertext} map")
        target = namespace or backup.get("namespace")
        if not isinstance(target, str) or not target:
            raise OpenRecallError("backup has no namespace; pass --dest-namespace")
        source = backup.get("namespace")
        original = self.namespace

        if target == source:
            self.put_entries(dict(entries))
            return {"namespace": target, "restored": len(entries), "reencrypted": False}

        # Cross-namespace: re-encrypt plaintext under the target namespace key.
        source_client = OpenRecallClient(
            url=self.url, namespace=str(source), passphrase=self._passphrase,
            api_key=self.api_key,
        )
        target_key = _derive_key(self._passphrase, target, SALT_PREFIX)
        restored: Dict[str, str] = {}
        for key, b64 in entries.items():
            plaintext, _prefix = source_client.decrypt_any(key, b64)
            restored[key] = encrypt_entry(target_key, key, plaintext)
        self.namespace = target
        try:
            self.put_entries(restored)
        finally:
            self.namespace = original
        return {"namespace": target, "restored": len(restored), "reencrypted": True}

    def rekey_namespace(self, new_passphrase: str, backup_path: str) -> Dict[str, Any]:
        """Re-encrypt every entry under ``new_passphrase`` and upload atomically.

        Writes a ciphertext backup to ``backup_path`` BEFORE uploading, verifies
        that every old entry decrypts and that each re-encrypted blob decrypts
        back to byte-identical plaintext, then does one delta PUT. Nothing is
        uploaded if any entry fails. Returns a summary; the caller must persist
        ``new_passphrase`` to the passphrase file after a successful return.
        """
        if not new_passphrase:
            raise OpenRecallError("new passphrase must not be empty")
        entries = self.get_namespace()
        if not entries:
            raise OpenRecallError("namespace is empty; nothing to rekey")

        # 1. Backup raw ciphertext first — recoverable even if rekey fails midway.
        backup = self.export_backup()
        with open(backup_path, "w", encoding="utf-8") as f:
            json.dump(backup, f, indent=2, sort_keys=True)
        os.chmod(backup_path, 0o600)

        # 2. Decrypt all with old passphrase, then re-encrypt under the new key.
        old_key = self._get_key()
        new_key = _derive_key(new_passphrase, self.namespace, SALT_PREFIX)
        reencrypted: Dict[str, str] = {}
        for key, b64 in entries.items():
            plaintext, _prefix = self.decrypt_any(key, b64)
            reencrypted[key] = encrypt_entry(new_key, key, plaintext)

        # 3. Verify the new blobs before touching the server. Compare
        #    plaintexts, not ciphertext blobs (fresh nonces differ).
        for key, b64 in reencrypted.items():
            original_pt = decrypt_entry(old_key, key, entries[key])
            if decrypt_entry(new_key, key, b64) != original_pt:
                raise OpenRecallError(f"rekey verification failed for {key!r}; nothing uploaded")

        # 4. Single delta PUT, then adopt the new key in this client.
        self.put_entries(reencrypted)
        self._passphrase = new_passphrase
        self._keys[SALT_PREFIX] = new_key
        return {
            "namespace": self.namespace,
            "rekeyed": len(reencrypted),
            "backup": backup_path,
            "verified": True,
        }

    # -- HTTP ----------------------------------------------------------------

    def _opener(self) -> urllib.request.OpenerDirector:
        """Return the opener used for every request (same-origin redirects only)."""
        opener = getattr(self, "_http_opener", None)
        if opener is None:
            opener = urllib.request.build_opener(_SameOriginRedirectHandler())
            self._http_opener = opener
        return opener

    def _request(self, method: str, path: str, body: Optional[dict] = None,
                 query: Optional[Dict[str, str]] = None,
                 timeout: Optional[float] = None) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.url}{path}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Accept": "application/json"} | (
                {"Content-Type": "application/json"} if data is not None else {}
            ),
        )
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with self._opener().open(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body_text)
            except Exception:
                parsed = {"error": body_text}
            return e.code, parsed
        except urllib.error.URLError as e:
            raise OpenRecallError(f"connection error: {e.reason}") from e

    def health(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Return the server /health JSON. Raises on connection failure."""
        status, payload = self._request("GET", "/health", timeout=timeout)
        return payload

    def is_alive(self, timeout: float = 5.0) -> bool:
        """Quick liveness check (does a /health request). Use sparingly."""
        try:
            payload = self.health(timeout=timeout)
            return bool(payload.get("ok"))
        except Exception as e:
            logger.debug("openrecall health check failed: %s", e)
            return False

    # -- Entries -------------------------------------------------------------

    def get_namespace(self) -> Dict[str, str]:
        """Return the full ``{key: ciphertext}`` map for the namespace.

        Normalizes the server response: the live server wraps entries under
        ``content.entries``; older/alt shapes are accepted.
        """
        status, payload = self._request("GET", f"/api/memory/{self.namespace}")
        if status >= 400:
            return {}
        return _extract_entries(payload)

    def put_entries(self, entries: Dict[str, str], deletions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Upsert entries (and optionally delete) in one round-trip.

        The server expects ``{"entries": {k: b64ct}}``; the deletion list is
        also accepted by the wire but is folded into a follow-up DELETE per
        key to keep the client contract small.
        """
        status, payload = self._request("PUT", f"/api/memory/{self.namespace}", body={"entries": entries})
        if status >= 400:
            raise OpenRecallError(f"PUT failed: HTTP {status} {payload}")
        for key in deletions or ():
            self.delete(key)
        return payload

    def delete(self, entry_key: str) -> bool:
        status, _ = self._request("DELETE", f"/api/memory/{self.namespace}", query={"key": entry_key})
        return status < 400

    # -- High-level (encryption-aware) --------------------------------------

    def save(self, entry_key: str, content: str) -> None:
        """Encrypt ``content`` under ``entry_key`` and upload to the namespace."""
        ct = encrypt_entry(self._get_key(), entry_key, content)
        self.put_entries({entry_key: ct})

    def recall(self, query: str = "") -> List[Tuple[str, str]]:
        """Return ``[(key, plaintext), ...]`` filtered and ranked by ``query``.

        Empty ``query`` returns all entries (decrypted). Non-empty queries
        are tokenized (stopwords dropped) and each entry is scored against
        the terms — matches in the entry key and YAML frontmatter
        ``description:`` weigh more than body hits, and entries covering
        more of the query terms rank higher (mirrors the upstream server's
        ``src/mcp/relevance.ts`` ranker). Any single-term substring hit
        still qualifies an entry, so single-term behavior is a superset of
        the legacy exact-substring filter; multi-word prompts (the shape
        Hermes feeds ``prefetch``) now return ranked hits instead of 0.
        Decryption failures are logged and skipped.
        """
        entries = self.get_namespace()
        q = query.lower() if query else ""
        out: List[Tuple[str, str]] = []
        for k, b64 in entries.items():
            try:
                pt, _prefix = self.decrypt_any(k, b64)
            except Exception as e:
                logger.debug("openrecall decrypt failed for %s: %s", k, e)
                continue
            out.append((k, pt))
        if not q:
            return out
        # Rank over ALL entries — term coverage is the filter (an exact
        # whole-string substring hit earns a bonus inside the ranker).
        return _rank_entries(q, out)

    def list_keys(self) -> List[str]:
        """Return all entry keys in the namespace (no decryption)."""
        return list(self.get_namespace().keys())

    # -- Salt migration ------------------------------------------------------

    def plan_salt_migration(self) -> Dict[str, Any]:
        """Describe what ``migrate_salt(apply=True)`` would do. Reads only."""
        entries = self.get_namespace()
        plan: Dict[str, Any] = {
            "namespace": self.namespace,
            "total": len(entries),
            "current": 0,
            "legacy": [],
            "undecryptable": [],
        }
        for k, b64 in entries.items():
            try:
                _pt, prefix = self.decrypt_any(k, b64)
            except Exception:
                plan["undecryptable"].append(k)
                continue
            if prefix == SALT_PREFIX:
                plan["current"] += 1
            else:
                plan["legacy"].append(k)
        return plan

    def _backup_path(self, path: Optional[str] = None) -> str:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        default = os.path.join(
            os.path.expanduser("~"), ".openrecall", f"salt-migration-{stamp}.json"
        )
        return path or default

    def migrate_salt(self, apply: bool = False, backup_path: Optional[str] = None) -> Dict[str, Any]:
        """Re-encrypt legacy ``memlawb:`` entries under the current salt prefix.

        Dry run by default. With ``apply=True`` it writes a rollback file holding the
        ORIGINAL ciphertext for every entry it rewrites, then verifies the result by
        re-reading the namespace and decrypting every migrated entry. The rollback
        file is written before any upload, so an interrupted run is recoverable by
        :func:`rollback_salt`.
        """
        entries = self.get_namespace()
        plan = self.plan_salt_migration()
        result: Dict[str, Any] = {
            "namespace": self.namespace,
            "dry_run": not apply,
            "total": plan["total"],
            "already_current": plan["current"],
            "to_migrate": len(plan["legacy"]),
            "undecryptable": plan["undecryptable"],
            "migrated": 0,
            "verified": None,
            "backup": None,
        }
        if not plan["legacy"]:
            return result

        rewrites: Dict[str, str] = {}
        digests: Dict[str, str] = {}
        for k in plan["legacy"]:
            pt, _prefix = self.decrypt_any(k, entries[k])
            digests[k] = hashlib.sha256(pt.encode("utf-8")).hexdigest()
            rewrites[k] = encrypt_entry(self._get_key(), k, pt)
        if not apply:
            return result

        backup = self._backup_path(backup_path)
        os.makedirs(os.path.dirname(backup), exist_ok=True)
        payload = {
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": self.url,
            "namespace": self.namespace,
            "salt_prefix": SALT_PREFIX,
            "legacy_salt_prefix": LEGACY_SALT_PREFIX,
            "entries": {k: entries[k] for k in rewrites},
        }
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        result["backup"] = backup

        self.put_entries(rewrites)
        result["migrated"] = len(rewrites)

        after = self.get_namespace()
        bad: List[str] = []
        for k, digest in digests.items():
            try:
                pt, prefix = self.decrypt_any(k, after[k])
            except Exception:
                bad.append(k)
                continue
            if prefix != SALT_PREFIX or hashlib.sha256(pt.encode("utf-8")).hexdigest() != digest:
                bad.append(k)
        result["verified"] = not bad
        result["failed_keys"] = bad
        return result


# -----------------------------------------------------------------------
# Module-level helpers (used by __init__.py, cli.py, and config_schema.py)
# -----------------------------------------------------------------------

def _read_scoped_secret(name: str) -> str:
    """Read a secret through Hermes' profile scope, failing closed.

    With Hermes importable, ``agent.secret_scope.get_secret`` resolves the
    active profile's value. When multiplexing is on but no scope is installed
    it raises; that is a configuration error, and returning "" (passphrase
    missing) is the safe outcome — reading ``os.environ`` instead would return
    another profile's secret.
    """
    try:
        from agent.secret_scope import get_secret  # type: ignore
    except Exception:
        # Standalone use (tests, `hermes openrecall` outside the agent): no
        # scope exists, so the process environment is the only source.
        return os.environ.get(name, "") or ""
    try:
        return get_secret(name) or ""
    except Exception as exc:
        logger.warning("%s unresolved (no profile secret scope): %s", name, exc)
        return ""


#: Env var holding the optional bearer token for a hosted openrecall server.
#: The wizard writes it to ``$HERMES_HOME/.env``; read it through the same
#: profile scope as the passphrase, never from ``config.yaml``.
API_KEY_ENV = "OPENRECALL_API_KEY"


def read_api_key() -> str:
    """Resolve the API key from the profile-scoped ``OPENRECALL_API_KEY``.

    A key left in ``config.yaml`` is deliberately ignored: tek's 2026-11-26
    review found the wizard writes the secret to ``.env`` while the provider
    only read the config block, so an authenticated server rejected every
    call after setup. Reading through the scope keeps profiles isolated.
    """
    return _read_scoped_secret(API_KEY_ENV)


def _configured_passphrase_file() -> str:
    """Return ``memory.openrecall.passphrase_file``, or "" when unset."""
    try:
        from hermes_cli.config import load_config_readonly  # type: ignore

        cfg = load_config_readonly() or {}
        memory = cfg.get("memory") if isinstance(cfg, dict) else None
        block = memory.get("openrecall") if isinstance(memory, dict) else None
        if isinstance(block, dict):
            path = block.get(PASSPHRASE_FILE_CONFIG_KEY)
            if path:
                return str(path)
    except Exception:
        return ""
    return ""


def read_passphrase(passphrase_file: Optional[str] = None) -> str:
    """Resolve the passphrase: profile-scoped env secret, then an explicit file.

    ``OPENRECALL_PASSPHRASE`` is read via ``agent.secret_scope.get_secret``
    when Hermes is present (see :func:`_read_scoped_secret`).

    The file fallback is opt-in: pass ``passphrase_file`` or set
    ``memory.openrecall.passphrase_file``. There is no default path — the old
    ``~/.openrecall-passphrase.txt`` / ``/run/secrets/*`` probing was shared by
    every profile on the host, and the ``MEMLAWB_*`` alias was an undeclared
    second credential name. Both are gone; legacy hosts set
    ``OPENRECALL_PASSPHRASE`` instead.
    """
    env_pw = _read_scoped_secret(PASSPHRASE_ENV)
    if env_pw:
        return env_pw

    path = _configured_passphrase_file() if passphrase_file is None else str(passphrase_file)
    if not path:
        return ""
    try:
        path = os.path.expanduser(path)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
    except OSError:
        return ""
    return ""


def _extract_entries(data: Any) -> Dict[str, str]:
    """Normalize the GET /api/memory/:ns response to ``{key: b64ct}``.

    Live server shape: ``{"content": {"entries": {k: v}}}``.
    Legacy / alt: top-level ``entries`` or ``data``.
    """
    if not isinstance(data, dict):
        return {}
    content = data.get("content")
    if isinstance(content, dict):
        entries = content.get("entries")
        if isinstance(entries, dict):
            return dict(entries)
    for key in ("entries", "data"):
        entries = data.get(key)
        if isinstance(entries, dict):
            return dict(entries)
    return {}


def rollback_salt(backup_path: str, url: Optional[str] = None,
                  passphrase: Optional[str] = None,
                  client: Optional["OpenRecallClient"] = None) -> Dict[str, Any]:
    """Restore the original ciphertext recorded by :meth:`OpenRecallClient.migrate_salt`.

    The backup file holds the pre-migration ciphertext, so a rollback is a plain
    upload of bytes that were already on the server: it cannot corrupt entries the
    migration did not touch. Verification re-reads every restored key and requires
    both a successful decrypt and byte-identical ciphertext.
    """
    with open(backup_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    entries: Dict[str, str] = data.get("entries") or {}
    if client is None:
        client = OpenRecallClient(
            url=url or data.get("url") or DEFAULT_URL,
            namespace=data.get("namespace") or DEFAULT_NAMESPACE,
            passphrase=passphrase,
        )
    result: Dict[str, Any] = {
        "backup": backup_path,
        "namespace": client.namespace,
        "restored": 0,
        "verified": False,
        "failed_keys": [],
    }
    if not entries:
        return result
    client.put_entries(entries)
    result["restored"] = len(entries)
    after = client.get_namespace()
    bad: List[str] = []
    for key, original in entries.items():
        try:
            client.decrypt_any(key, after[key])
        except Exception:
            bad.append(key)
            continue
        if after.get(key) != original:
            bad.append(key)
    result["failed_keys"] = bad
    result["verified"] = not bad
    return result
