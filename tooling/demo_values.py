"""Generate deterministic reference values for the recovery fixture demo.

Run from the repository root with ``PYTHONPATH=src python3 tooling/demo_values.py``.
It builds the exact timeline described in the README in a temporary directory
and prints every independent expected value the tests assert against.
"""
import hashlib
import json
import tempfile
from pathlib import Path

from mailroom import collection, recovery, review, vault

FIX = Path("fixtures/recovery")
M = "<crane@example.invalid>"
D = "<crane-reply@example.invalid>"
K = "<supplier@example.invalid>"
OLD = "<legacy@example.invalid>"
N = "<late@example.invalid>"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(root):
    db = root / "vault.sqlite"
    vault.init(FIX / "batch1", db)
    recovery.enable(db)
    vault.retention_plan(db, "RECOVERY-OLD", "2026-11-02T12:00:00Z")
    vault.retention_apply(db, "RECOVERY-OLD")
    review.review_open(db, FIX / "spec-m.json")
    review.review_open(db, FIX / "spec-k.json")
    package_m = root / "ext-m.json"
    review.review_export(db, "RECOVERY-M", package_m)
    package_k = root / "ext-k.json"
    review.review_export(db, "RECOVERY-K", package_k)
    feedback = root / "feedback-m.json"
    feedback.write_text(json.dumps({
        "review_id": "RECOVERY-M",
        "package_sha256": json.loads(package_m.read_text())["package_sha256"],
        "return_id": "RETURN-M",
        "annotations": [{"annotation_id": "NOTE-M", "item_id": "M0001",
                         "start": 0, "end": 5,
                         "comment": "Crane bracket quoted by reviewer."}],
    }))
    review.review_return(db, "RECOVERY-M", package_m, feedback)
    collection.collection_import(db, FIX / "manifest.json")
    checkpoint = root / "C.json"
    recovery.checkpoint(db, checkpoint)
    checkpoint_revision = recovery.info(db)["revision"]
    vault.retention_plan(db, "RECOVERY-M-PURGE", "2026-11-03T09:30:00Z")
    vault.retention_apply(db, "RECOVERY-M-PURGE")
    vault.ingest(FIX / "later", db)
    authority = root / "A.json"
    recovery.authority(db, authority)
    return checkpoint, authority, checkpoint_revision, package_m, package_k


def main():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        checkpoint, authority, revision, package_m, package_k = build(root)
        recovered = root / "recovered.sqlite"
        result = recovery.restore(
            checkpoint, sha(checkpoint), authority, sha(authority), revision,
            recovered)
        values = {
            "checkpoint_sha256": sha(checkpoint),
            "checkpoint_revision": revision,
            "authority_sha256": sha(authority),
            "authority_revision": result["authority_revision"],
            "suppressed": result["suppressed"],
            "package_m_sha256": sha(package_m),
            "package_k_sha256": sha(package_k),
            "recovered_size": recovered.stat().st_size,
            "thread_d": vault.vault_thread(recovered, D),
            "search_cracked": vault.vault_search(recovered, "cracked"),
            "search_bearings": [r["id"] for r in
                                vault.vault_search(recovered, "bearings")],
            "notes_m": review.review_notes(recovered, M),
            "provenance_m": collection.vault_provenance(recovered, M),
            "retention_old": vault.retention_show(recovered, "RECOVERY-OLD"),
            "contains_suppressed_subject": b"Crane inspection report"
            in recovered.read_bytes(),
            "contains_suppressed_body": b"cracked bracket on pier seven"
            in recovered.read_bytes(),
        }
        print(json.dumps(values, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
