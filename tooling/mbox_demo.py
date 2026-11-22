"""Generate deterministic reference values for the mboxrd intake demo.

Run from the repository root with ``PYTHONPATH=src python3 tooling/mbox_demo.py``.
It builds the custodian append / quarantine / replace / certify timeline in a
temporary directory and prints every independently computed expected value
(record range hashes, pinned prefix digests, sealed file digest, replacement
digest and certificate digest), so the behavior can be re-checked without
trusting values produced by the module under test.
"""
import hashlib
import json
import tempfile
from pathlib import Path

from mailroom import mbox, vault

A = "<anchor-a@example.invalid>"
P = "<parent-p@example.invalid>"
R = "<reply-r@example.invalid>"


def eml(msg_id, parent=None, body="evidence body"):
    headers = [
        "From: custodian@example.invalid", "To: investigator@example.invalid",
        "Date: Tue, 03 Nov 2026 09:00:00 +0000", f"Message-ID: {msg_id}",
        "Subject: Mbox intake", "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8"]
    if parent is not None:
        headers.append(f"In-Reply-To: {parent}")
    return ("\n".join(headers) + "\n\n" + body + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(root):
    seed = root / "seed"
    seed.mkdir()
    # Baseline R replies to a missing parent P; anchor A is external.
    (seed / "r.eml").write_bytes(eml(R, parent=P, body="reply waiting on P"))
    db = root / "vault.sqlite"
    vault.init(seed, db)
    vault.hold_add(db, "HOLD-A", A)
    vault.retention_plan(db, "PURGE-PLAN", "2026-12-31T00:00:00Z")

    mailbox = root / "custodian.mbox"
    env_p = b"From custodian Mon Nov  2 08:00:00 2026\n"
    broken_p = b"this physical record is not a valid MIME message at all\n\n"
    env_s = b"From custodian Mon Nov  2 09:00:00 2026\n"
    s_mail = eml("<witness-s@example.invalid>")
    env_x = b"From custodian Mon Nov  2 10:00:00 2026\n"
    x_mail = eml("<witness-x@example.invalid>")
    # First delivery: P broken, S complete, X unfinished (no next envelope).
    first = env_p + broken_p + env_s + s_mail + env_x + x_mail[:60]
    mailbox.write_bytes(first)
    first_show = mbox.mbox_scan(db, "CASE-1", mailbox)

    # Custodian appends the rest of X and the envelope that closes its record.
    env_x2 = b"From custodian Mon Nov  2 11:00:00 2026\n"
    x2_mail = eml("<witness-x2@example.invalid>")
    second = first + x_mail[60:] + env_x2 + x2_mail
    mailbox.write_bytes(second)
    second_show = mbox.mbox_scan(db, "CASE-1", mailbox)

    # Investigator replaces the broken P with valid mail chained to anchor A.
    replacement = eml(P, parent=A, body="P recovered, replies to anchor A")
    fix = root / "p-replacement.eml"
    fix.write_bytes(replacement)
    decision = root / "decision.json"
    decision.write_text(json.dumps({
        "source_id": "CASE-1",
        "record_number": 1,
        "record_sha256": first_show["records"][0]["record_sha256"],
        "action": "replace",
        "reason": "P record was invalid; replaced with recovered mail to A",
        "replacement": "p-replacement.eml",
    }))
    resolved = mbox.mbox_resolve(db, decision)

    sealed_bytes = second
    sealed_show = mbox.mbox_scan(db, "CASE-1", mailbox, seal=True)
    certificate = mbox.mbox_certify(db, "CASE-1")

    values = {
        "first_scan_statuses": [
            (item["record_number"], item["status"], item.get("reason"))
            for item in first_show["records"]],
        "second_scan_numbers": [item["record_number"]
                                for item in second_show["records"]],
        "broken_record_range": [first_show["records"][0]["start"],
                                first_show["records"][0]["end"]],
        "broken_record_sha256_expected": sha(env_p + broken_p),
        "broken_record_sha256_ledger": first_show["records"][0]["record_sha256"],
        "s_record_sha256_expected": sha(env_s + s_mail),
        "replacement_sha256": sha(replacement),
        "resolved_status": resolved["status"],
        "resolved_initial_reason": resolved["initial_reason"],
        "sealed_source_bytes": len(sealed_bytes),
        "sealed_source_sha256_expected": sha(sealed_bytes),
        "sealed_source_sha256_ledger": sealed_show["source_sha256"],
        "certificate_records": [(item["record_number"], item["status"])
                                for item in certificate["records"]],
        "certificate_digest": sha(json.dumps(
            certificate, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()),
        "r_thread_root_after_replace":
            vault.vault_thread(db, R)[0]["thread_id"],
    }
    return values


def main():
    with tempfile.TemporaryDirectory() as tmp:
        print(json.dumps(build(Path(tmp)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
