"""Backup / restore / verify / rekey gates — no live server touched.

Uses a stubbed ``get_namespace`` / ``put_entries`` so these tests are pure and
fast. Covers the safety properties: backups contain no plaintext, restore
refuses bad input before writing, rekey verifies before upload and writes a
backup first, and a wrong passphrase cannot read rekeyed entries.
"""

from __future__ import annotations

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from openrecall_provider.client import OpenRecallClient, OpenRecallError  # noqa: E402


PW = "test-passphrase-alpha"
NEW_PW = "test-passphrase-bravo"
NS = "user:test-backup"


def make_client(pw=PW, store=None):
    c = OpenRecallClient(url="http://127.0.0.1:1", namespace=NS, passphrase=pw)
    store = store if store is not None else {}
    c.get_namespace = lambda: dict(store)  # type: ignore[method-assign]
    c.put_entries = lambda entries, deletions=None: (  # type: ignore[method-assign]
        store.update(entries) or {}
    )
    return c, store


def test_export_contains_no_plaintext():
    c, store = make_client()
    c.save("k1", "SECRET-PLAINTEXT-XYZ")
    backup = c.export_backup()
    blob = json.dumps(backup)
    assert backup["format"] == "openrecall-backup"
    assert backup["namespace"] == NS
    assert "SECRET-PLAINTEXT-XYZ" not in blob
    assert "passphrase" not in blob.lower()


def test_restore_roundtrip_into_fresh_store(monkeypatch):
    c1, store1 = make_client()
    c1.save("k1", "hello")
    c1.save("k2", "world")
    backup = c1.export_backup()

    c2, store2 = make_client()
    # Cross-namespace restore builds a source client for the export's NS.
    monkeypatch.setattr(
        "openrecall_provider.client.OpenRecallClient",
        lambda **kw: type("C", (), {"decrypt_any": lambda self, k, v: c1.decrypt_any(k, v)})(),
    )
    result = c2.restore_backup(backup, namespace="user:restored")
    assert result == {"namespace": "user:restored", "restored": 2, "reencrypted": True}
    assert set(store2) == {"k1", "k2"}
    # Re-encrypted under the target namespace key: the source ciphertext is NOT copied.
    assert store2 != backup["entries"]
    target_client = OpenRecallClient(
        url="http://127.0.0.1:1", namespace="user:restored", passphrase=PW
    )
    target_client._keys["openrecall:"] = __import__(
        "openrecall_provider.client", fromlist=["_derive_key"]
    )._derive_key(PW, "user:restored", "openrecall:")
    assert target_client.decrypt_any("k1", store2["k1"])[0] == "hello"


def test_restore_refuses_bad_file_before_writing():
    c, store = make_client()
    for bad in ({}, {"format": "other", "entries": {}},
                {"format": "openrecall-backup", "version": 99, "entries": {}},
                {"format": "openrecall-backup", "version": 1, "entries": {"k": 7}}):
        try:
            c.restore_backup(bad)
        except OpenRecallError:
            pass
        else:
            raise AssertionError(f"bad backup accepted: {bad}")
        assert store == {}, "restore wrote something before refusing"


def test_verify_counts_all_entries():
    c, _ = make_client()
    c.save("k1", "a")
    c.save("k2", "b")
    result = c.verify_entries()
    assert result["total"] == 2
    assert result["decrypted"] == 2
    assert result["failed"] == 0
    assert result["salt_prefixes"] == {"openrecall:": 2}


def test_verify_detects_corruption():
    c, store = make_client()
    c.save("k1", "a")
    store["k1"] = "not-valid-ciphertext"
    result = c.verify_entries()
    assert result["failed"] == 1
    assert result["decrypted"] == 0


def test_rekey_rewrites_ciphertext_and_writes_backup(tmp_path):
    c, store = make_client()
    c.save("k1", "top-secret-value")
    old_ct = dict(store)
    backup_path = str(tmp_path / "backup.json")

    result = c.rekey_namespace(NEW_PW, backup_path)
    assert result["verified"] is True
    assert result["rekeyed"] == 1
    assert os.path.isfile(backup_path)
    assert oct(os.stat(backup_path).st_mode & 0o777) == "0o600"

    saved_backup = json.load(open(backup_path))
    assert saved_backup["entries"] == old_ct, "backup must hold the ORIGINAL ciphertext"

    # New passphrase reads the rekeyed entry; old passphrase cannot.
    assert c.recall("top-secret-value")[0][1] == "top-secret-value"
    c_old, _ = make_client(pw=PW, store=store)
    assert c_old.recall("top-secret-value") == []


def test_rekey_refuses_empty_namespace(tmp_path):
    c, _ = make_client()
    try:
        c.rekey_namespace(NEW_PW, str(tmp_path / "b.json"))
    except OpenRecallError:
        pass
    else:
        raise AssertionError("empty namespace rekey should be refused")
    assert not os.path.exists(str(tmp_path / "b.json"))


def test_rekey_does_not_upload_on_corrupt_entry(tmp_path):
    c, store = make_client()
    c.save("k1", "good")
    store["k2"] = "corrupt"
    before = dict(store)
    try:
        c.rekey_namespace(NEW_PW, str(tmp_path / "b.json"))
    except Exception:
        pass
    else:
        raise AssertionError("corrupt entry must abort rekey")
    assert store == before, "nothing may be uploaded when verification fails"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
