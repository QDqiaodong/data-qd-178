"""Recovery tracking, checkpoints, authority and read-only restore contracts."""
import contextlib
import hashlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mailroom import cli, collection, recovery, review, vault
from mailroom.archive import build as v1_build

R = "<r@example.invalid>"
P = "<p@example.invalid>"
A = "<a@example.invalid>"
M = "<crane@example.invalid>"
D = "<crane-reply@example.invalid>"
K = "<supplier@example.invalid>"
OLD = "<legacy@example.invalid>"
N = "<late@example.invalid>"

CANONICAL_KW = dict(ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False)
FIX = Path("fixtures/recovery")


def write_eml(directory, name, msg_id, parent=None,
              date="Tue, 03 Nov 2026 08:00:00 +0000", subject="Note",
              body="body text", sender="a@example.invalid"):
    headers = [f"From: {sender}", "To: b@example.invalid", f"Date: {date}",
               f"Message-ID: {msg_id}"]
    if parent is not None:
        headers.append(f"In-Reply-To: {parent}")
    headers += [f"Subject: {subject}", "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8"]
    path = Path(directory) / name
    path.write_text("\n".join(headers) + "\n\n" + body + "\n")
    return path


def canonical(value):
    return json.dumps(value, **CANONICAL_KW).encode("utf-8")


def file_digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def table_digest(db_path):
    """Independent digest of the logical business tables (no recovery state)."""
    db = sqlite3.connect(db_path)
    try:
        digest = hashlib.sha256()
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vault_%' "
            "ORDER BY name") if row[0] != "vault_recovery_state"
            and not row[0].startswith("vault_search")]
        for name in names:
            digest.update(name.encode())
            for row in db.execute(f'SELECT * FROM "{name}" ORDER BY rowid'):
                digest.update(repr(row).encode())
        return digest.hexdigest()
    finally:
        db.close()


def create_authority(path, vault_id, stream, revision, purged):
    """Write an authority file independently of the exporter, then return bytes."""
    document = {"format": "mailroom-recovery-authority-1", "vault": vault_id,
                "stream": stream, "revision": revision, "purged": purged}
    payload = canonical(document)
    Path(path).write_bytes(payload)
    return payload


class RecoveryCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"

    def batch(self, name, spec):
        folder = self.root / name
        folder.mkdir()
        for number, item in enumerate(spec):
            msg_id, parent, body = item
            write_eml(folder, f"{number:03}.eml", msg_id, parent=parent, body=body)
        return folder

    def init(self, spec=((R, None, "ledger body"), (P, R, "reply body"))):
        vault.init(self.batch("seed", spec), self.db)
        return recovery.enable(self.db)

    def info(self):
        return recovery.info(self.db)

    def query(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.root.iterdir()
                if path.is_file()}

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", ["mail-archive", *argv]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


class EnableTests(RecoveryCase):
    def test_enable_keeps_identity_and_business_state(self):
        folder = self.batch("seed", ((R, None, "ledger body"),))
        before = vault.init(folder, self.db)
        digest_before = table_digest(self.db)
        result = recovery.enable(self.db)
        self.assertEqual(list(result), ["mode", "vault", "stream", "revision",
                                        "checkpoint_sha256", "authority_sha256",
                                        "authority_revision", "suppressed"])
        self.assertEqual(result["mode"], "source")
        self.assertEqual(result["vault"], before["vault"])
        self.assertEqual(result["revision"], 0)
        self.assertEqual(result["checkpoint_sha256"], None)
        self.assertEqual(result["authority_sha256"], None)
        self.assertEqual(result["authority_revision"], None)
        self.assertEqual(result["suppressed"], [])
        self.assertRegex(result["stream"], r"^[0-9a-f]{32}$")
        self.assertEqual(table_digest(self.db), digest_before)

    def test_enable_retry_returns_original_identity_and_watermark(self):
        first = self.init()
        folder = self.batch("next", ((A, None, "another"),))
        vault.ingest(folder, self.db)
        second = recovery.enable(self.db)
        self.assertEqual(second, {**first, "revision": 1})

    def test_enable_rejects_v1_missing_and_recovered_without_changes(self):
        v1 = self.root / "v1.sqlite"
        v1_build("fixtures/mail", v1)
        digest = v1.read_bytes()
        with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
            recovery.enable(v1)
        self.assertEqual(v1.read_bytes(), digest)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            recovery.enable(self.root / "missing.sqlite")
        self.assertFalse((self.root / "missing.sqlite").exists())
        self.init()
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        copy = self.root / "copy.sqlite"
        recovery.restore(checkpoint, file_digest(checkpoint), authority,
                         file_digest(authority), 0, copy)
        digest = copy.read_bytes()
        with self.assertRaises(vault.RecoveredVault):
            recovery.enable(copy)
        self.assertEqual(copy.read_bytes(), digest)

    def test_untracked_vault_rejects_other_recovery_commands(self):
        vault.init(self.batch("seed", ((R, None, "x"),)), self.db)
        with self.assertRaisesRegex(ValueError, "not enabled"):
            recovery.info(self.db)
        with self.assertRaisesRegex(ValueError, "not enabled"):
            recovery.checkpoint(self.db, self.root / "c.json")
        with self.assertRaisesRegex(ValueError, "not enabled"):
            recovery.authority(self.db, self.root / "a.json")
        self.assertFalse((self.root / "c.json").exists())
        self.assertFalse((self.root / "a.json").exists())
        # ordinary commands still work exactly as before
        self.assertEqual(vault.hold_add(self.db, "H", A)["state"], "active")
        self.assertEqual(recovery.enable(self.db)["revision"], 0)

    def test_missing_recovery_commands_do_not_create_database(self):
        missing = self.root / "nope.sqlite"
        for call in (lambda: recovery.info(missing),
                     lambda: recovery.checkpoint(missing, self.root / "c"),
                     lambda: recovery.authority(missing, self.root / "a")):
            with self.assertRaises((ValueError, sqlite3.Error)):
                call()
        self.assertFalse(missing.exists())


class RevisionTests(RecoveryCase):
    def test_every_mutating_operation_advances_exactly_once(self):
        self.init(((R, None, "ledger body"),))
        self.assertEqual(self.info()["revision"], 0)
        # three new identities in one ingest: a single step
        vault.ingest(self.batch("b2", ((P, R, "one"), (A, None, "two"),
                                      (M, None, "three"))), self.db)
        self.assertEqual(self.info()["revision"], 1)
        vault.hold_add(self.db, "H", A)
        self.assertEqual(self.info()["revision"], 2)
        vault.hold_release(self.db, "H")
        self.assertEqual(self.info()["revision"], 3)
        vault.retention_plan(self.db, "P1", "2026-01-01T00:00:00Z")  # empty plan
        self.assertEqual(self.info()["revision"], 4)
        vault.retention_apply(self.db, "P1")  # empty receipt is real business
        self.assertEqual(self.info()["revision"], 5)
        spec = self.root / "spec.json"
        spec.write_bytes(canonical({"review_id": "R1", "messages": [
            {"message_id": R, "redactions": []}]}))
        review.review_open(self.db, spec)
        self.assertEqual(self.info()["revision"], 6)
        package = self.root / "pkg.json"
        review.review_export(self.db, "R1", package)
        self.assertEqual(self.info()["revision"], 6)  # export changes nothing
        feedback = self.root / "fb.json"
        feedback.write_bytes(canonical({
            "review_id": "R1",
            "package_sha256": json.loads(package.read_text())["package_sha256"],
            "return_id": "T1",
            "annotations": [{"annotation_id": "X1", "item_id": "M0001",
                             "start": 0, "end": 3, "comment": "note"}]}))
        review.review_return(self.db, "R1", package, feedback)
        self.assertEqual(self.info()["revision"], 7)
        manifest = self.root / "manifest.json"
        manifest.write_bytes(canonical({
            "intake_id": "C1", "packages": [{
                "package_id": "PK", "custodian": "CU", "value": 1,
                "source": str(self.root / "b2")}]}))
        collection.collection_import(self.db, manifest)
        self.assertEqual(self.info()["revision"], 8)

    def test_successful_replays_and_noops_do_not_advance(self):
        self.init(((R, None, "ledger body"),))
        vault.ingest(self.batch("same", ((R, None, "ledger body"),)), self.db)
        self.assertEqual(self.info()["revision"], 0)  # identical redelivery
        vault.hold_add(self.db, "H", A)
        vault.hold_add(self.db, "H", A)
        vault.hold_release(self.db, "H")
        vault.hold_release(self.db, "H")
        vault.retention_plan(self.db, "P", "2026-01-01T00:00:00Z")
        vault.retention_plan(self.db, "P", "2026-01-01T00:00:00Z")
        vault.retention_apply(self.db, "P")
        vault.retention_apply(self.db, "P")
        self.assertEqual(self.info()["revision"], 4)  # add, release, plan, apply
        vault.vault_search(self.db, "ledger")
        vault.vault_thread(self.db, R)
        vault.retention_show(self.db, "P")
        self.assertEqual(self.info()["revision"], 4)
        with self.assertRaises(ValueError):
            vault.retention_apply(self.db, "NOPE")
        with self.assertRaises(ValueError):
            vault.hold_release(self.db, "NOPE")
        self.assertEqual(self.info()["revision"], 4)

    def test_empty_selection_collection_and_empty_purge_are_business(self):
        self.init(((R, None, "ledger body"),))
        conflicting = self.batch("conflict", ((R, None, "different bytes"),))
        manifest = self.root / "manifest.json"
        manifest.write_bytes(canonical({
            "intake_id": "C1", "packages": [{
                "package_id": "PK", "custodian": "CU", "value": 1,
                "source": str(conflicting)}]}))
        result = collection.collection_import(self.db, manifest)
        self.assertEqual(result["selected_packages"], [])
        self.assertEqual(self.info()["revision"], 1)
        collection.collection_import(self.db, manifest)
        self.assertEqual(self.info()["revision"], 1)  # replay

    def test_failed_mutations_roll_back_business_and_revision(self):
        self.init(((R, None, "ledger body"),))
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.ingest(self.batch("late", ((P, None, "late body"),)), self.db)
        vault.retention_plan(self.db, "P2", "2026-11-04T00:00:00Z")
        self.assertEqual(self.info()["revision"], 3)
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.startswith(
                        "UPDATE vault_recovery_state"):
                    raise sqlite3.OperationalError("injected watermark crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect",
                        side_effect=lambda *a, **k: real_connect(
                            *a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                vault.retention_apply(self.db, "P")
        # payload removal and the receipt never committed, and neither did the
        # watermark: the two must never diverge.
        self.assertEqual(self.info()["revision"], 3)
        self.assertEqual(self.query("SELECT * FROM vault_receipts"), [])
        statuses = dict(self.query("SELECT id, status FROM vault_messages"))
        self.assertEqual(statuses[R], "live")
        self.assertEqual(vault.vault_search(self.db, "ledger")[0]["id"], R)

    def test_cli_and_library_calls_share_revision_semantics(self):
        self.init(((R, None, "ledger body"),))
        code, out, _ = self.run_cli("hold-add", "--db", str(self.db),
                                    "--hold-id", "H", "--anchor", A)
        self.assertEqual(code, 0)
        self.assertEqual(recovery.info(self.db)["revision"], 1)
        code, out, _ = self.run_cli("recovery-info", "--db", str(self.db))
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["revision"], 1)
        self.assertEqual(payload["mode"], "source")


class CheckpointTests(RecoveryCase):
    def test_checkpoint_refuses_forged_tables_before_publishing(self):
        # A source vault whose stored payload has been hand-edited into a shape
        # no reader would accept must not produce a checkpoint: the generator
        # validates the finished artefact exactly as a reader does.
        self.init()
        con = sqlite3.connect(self.db)
        try:
            con.execute("UPDATE vault_messages SET subject=NULL WHERE id=?", (R,))
            con.commit()
        finally:
            con.close()
        target = self.root / "c.json"
        with self.assertRaisesRegex(ValueError, "lacks text payload"):
            recovery.checkpoint(self.db, target)
        self.assertFalse(target.exists())
        self.assertEqual([p.name for p in self.root.iterdir()
                          if p.name.startswith(".recovery")], [])

    def test_checkpoint_is_canonical_self_contained_and_deterministic(self):
        self.init()
        first = self.root / "c1.json"
        second = self.root / "c2.json"
        result = recovery.checkpoint(self.db, first)
        recovery.checkpoint(self.db, second)
        self.assertEqual(list(result), ["vault", "stream", "revision", "sha256",
                                        "bytes"])
        raw = first.read_bytes()
        self.assertEqual(raw, second.read_bytes())
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["bytes"], len(raw))
        self.assertFalse(raw.endswith(b"\n"))
        document = json.loads(raw)
        self.assertEqual(raw, canonical(document))  # canonical key order/whitespace
        self.assertEqual(list(document), ["checksum", "format", "revision",
                                          "stream", "tables", "vault"])
        self.assertEqual(document["format"], "mailroom-recovery-checkpoint-1")
        base = {key: value for key, value in document.items() if key != "checksum"}
        self.assertEqual(document["checksum"],
                         hashlib.sha256(canonical(base)).hexdigest())
        self.assertEqual(set(document["tables"]), set(recovery.TABLE_NAMES))
        self.assertEqual(document["revision"], 0)
        self.assertEqual(result["stream"], self.info()["stream"])

    def test_checkpoint_omits_purged_payload_and_carries_live_payload(self):
        self.init()
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P")
        result = recovery.checkpoint(self.db, self.root / "c.json")
        raw = (self.root / "c.json").read_bytes()
        document = json.loads(raw)
        messages = {row[0]: row for row in
                    document["tables"]["vault_messages"]["rows"]}
        columns = document["tables"]["vault_messages"]["columns"]
        purged = dict(zip(columns, messages[R]))
        self.assertEqual(purged["status"], "purged")
        self.assertIsNone(purged["body"])
        self.assertIsNone(purged["source_bytes"])
        self.assertEqual(result["revision"], 2)
        # the checkpoint file is only published after full in-memory validation
        self.assertTrue(document["checksum"])

    def test_checkpoint_rejects_existing_output_and_recovered_vault(self):
        self.init()
        target = self.root / "c.json"
        target.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            recovery.checkpoint(self.db, target)
        self.assertEqual(target.read_bytes(), b"keep")
        dangling = self.root / "dangling.json"
        dangling.symlink_to(self.root / "missing-target")
        with self.assertRaises(FileExistsError):
            recovery.checkpoint(self.db, dangling)
        self.assertFalse((self.root / "missing-target").exists())
        first = self.root / "c1.json"
        recovery.checkpoint(self.db, first)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        copy = self.root / "copy.sqlite"
        recovery.restore(first, file_digest(first), authority,
                         file_digest(authority), 0, copy)
        with self.assertRaises(vault.RecoveredVault):
            recovery.checkpoint(copy, self.root / "c2.json")
        with self.assertRaises(vault.RecoveredVault):
            recovery.authority(copy, self.root / "a2.json")
        self.assertFalse((self.root / "c2.json").exists())
        self.assertFalse((self.root / "a2.json").exists())

    def test_publish_failure_leaves_no_output_or_temp_file(self):
        self.init()
        target = self.root / "c.json"
        with mock.patch("os.link", side_effect=OSError("injected link failure")):
            with self.assertRaises(OSError):
                recovery.checkpoint(self.db, target)
        self.assertFalse(target.exists())
        self.assertEqual([path.name for path in self.root.iterdir()
                          if path.name.startswith(".recovery")], [])
        authority_target = self.root / "a.json"
        with mock.patch("os.link", side_effect=OSError("injected link failure")):
            with self.assertRaises(OSError):
                recovery.authority(self.db, authority_target)
        self.assertFalse(authority_target.exists())
        self.assertEqual([path.name for path in self.root.iterdir()
                          if path.name.startswith(".recovery")], [])

    def test_checkpoint_without_review_or_collection_tables(self):
        self.init()
        result = recovery.checkpoint(self.db, self.root / "c.json")
        document = json.loads((self.root / "c.json").read_bytes())
        for name in ("vault_review_batches", "vault_collection_intakes",
                     "vault_collection_sources"):
            self.assertEqual(document["tables"][name]["rows"], [])
        self.assertEqual(result["revision"], 0)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        copy = self.root / "copy.sqlite"
        recovery.restore(self.root / "c.json", result["sha256"], authority,
                         file_digest(authority), 0, copy)
        self.assertEqual(review.review_notes(copy, R),
                         {"message_id": R, "annotations": []})
        self.assertEqual(collection.vault_provenance(copy, R),
                         {"message_id": R, "sources": []})
        self.assertEqual([row["id"] for row in vault.vault_search(copy, "ledger")], [R])


class AuthorityTests(RecoveryCase):
    def test_authority_is_strict_sorted_and_payload_free(self):
        self.init(((R, None, "unique ledger marker"), (P, R, "reply marker")))
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P")
        output = self.root / "a.json"
        result = recovery.authority(self.db, output)
        raw = output.read_bytes()
        document = json.loads(raw)
        self.assertEqual(list(result), ["vault", "stream", "revision", "sha256",
                                        "purged_count"])
        self.assertEqual(raw, canonical(document))
        self.assertEqual(set(document), {"format", "vault", "stream", "revision",
                                         "purged"})
        self.assertEqual(document["format"], "mailroom-recovery-authority-1")
        self.assertEqual([entry["message_id"] for entry in document["purged"]],
                         sorted([R, P]))
        for entry in document["purged"]:
            self.assertEqual(set(entry), {"message_id", "source_sha256"})
            self.assertRegex(entry["source_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(result["purged_count"], 2)
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        for marker in (b"unique ledger marker", b"reply marker", b"Subject",
                       b"a@example.invalid"):
            self.assertNotIn(marker, raw)

    def test_authority_empty_purged_is_still_an_object(self):
        self.init()
        output = self.root / "a.json"
        result = recovery.authority(self.db, output)
        document = json.loads(output.read_bytes())
        self.assertEqual(document["purged"], [])
        self.assertEqual(result["purged_count"], 0)
        self.assertEqual(document["revision"], 0)

    def test_authority_refuses_existing_output(self):
        self.init()
        target = self.root / "a.json"
        target.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            recovery.authority(self.db, target)
        self.assertEqual(target.read_bytes(), b"keep")


class RestoreValidationTests(RecoveryCase):
    def setUp(self):
        super().setUp()
        self.init()
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P")
        self.checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, self.checkpoint)
        self.authority_path = self.root / "a.json"
        recovery.authority(self.db, self.authority_path)
        self.csha = file_digest(self.checkpoint)
        self.asha = file_digest(self.authority_path)
        self.out = self.root / "out"
        self.out.mkdir()
        self.target = self.out / "copy.sqlite"

    def authority(self):
        return json.loads(self.authority_path.read_bytes())

    def write(self, name, document):
        path = self.root / name
        path.write_bytes(canonical(document))
        return path, file_digest(path)

    def assert_rejected(self, pattern, checkpoint=None, csha=None,
                        authority=None, asha=None, minimum=0):
        checkpoint = checkpoint or self.checkpoint
        csha = csha or file_digest(checkpoint)
        authority = authority or self.authority_path
        asha = asha or file_digest(authority)
        with self.assertRaisesRegex(ValueError, pattern):
            recovery.restore(checkpoint, csha, authority, asha, minimum,
                             self.target)
        self.assertFalse(self.target.exists())
        self.assertEqual(sorted(path.name for path in self.out.iterdir()), [])

    def test_external_byte_digests_are_mandatory(self):
        self.assert_rejected("checkpoint file digest", csha="0" * 64)
        self.assert_rejected("authority file digest", asha="0" * 64)
        self.assert_rejected("64 lowercase", csha="A" * 64)
        self.assert_rejected("64 lowercase", asha="f" * 63)
        self.assert_rejected("64 lowercase", asha="0" * 64 + "\n")

    def test_minimum_revision_and_origin_checks(self):
        self.assert_rejected("below the required minimum", minimum=3)
        document = self.authority()
        document["vault"] = "f" * 32
        path, digest = self.write("foreign-vault.json", document)
        self.assert_rejected("different vaults", authority=path, asha=digest)
        document = self.authority()
        document["stream"] = "e" * 32
        path, digest = self.write("foreign-stream.json", document)
        self.assert_rejected("different streams", authority=path, asha=digest)
        document = self.authority()
        document["revision"] = 0
        path, digest = self.write("old.json", document)
        self.assert_rejected("older than the checkpoint", authority=path, asha=digest)

    def test_authority_must_cover_checkpoint_purges(self):
        document = self.authority()
        document["purged"] = [entry for entry in document["purged"]
                              if entry["message_id"] != R]
        path, digest = self.write("missing.json", document)
        self.assert_rejected("omits an identity", authority=path, asha=digest)
        document = self.authority()
        for entry in document["purged"]:
            if entry["message_id"] == P:
                entry["source_sha256"] = "a" * 64
        path, digest = self.write("conflict.json", document)
        self.assert_rejected("digest conflict", authority=path, asha=digest)

    def test_same_revision_must_claim_the_same_purged_set(self):
        early = self.root / "early.json"
        recovery.authority(self.db, early)  # revision 1, both purged
        # Craft an authority at the checkpoint revision that also claims a
        # checkpoint-live identity as purged.
        document = json.loads(early.read_bytes())
        document["purged"].append({"message_id": "<ghost@example.invalid>",
                                   "source_sha256": "b" * 64})
        document["purged"].sort(key=lambda item: item["message_id"])
        path, digest = self.write("extra.json", document)
        self.assert_rejected("different purged set", authority=path, asha=digest)

    def test_malformed_materials_rejected(self):
        raw = bytearray(self.checkpoint.read_bytes())
        broken = self.root / "broken.json"
        # Flip one byte of a stored payload value; the content checksum must
        # catch it even though the file is still well-formed JSON.
        document = json.loads(raw)
        document["stream"] = "c" * 32
        # a well-formed but altered checkpoint is rejected by its checksum
        broken.write_bytes(canonical(document))
        self.assert_rejected("content checksum", checkpoint=broken)
        truncated = self.root / "truncated.json"
        truncated.write_bytes(self.checkpoint.read_bytes()[:120])
        self.assert_rejected("not valid JSON", checkpoint=truncated)
        document = self.authority()
        document["revision"] = True
        path, digest = self.write("bool.json", document)
        self.assert_rejected("integer", authority=path, asha=digest)
        document = json.loads(self.authority_path.read_bytes())
        document["extra"] = 1
        path, digest = self.write("extra-key.json", document)
        self.assert_rejected("exactly these keys", authority=path, asha=digest)
        duplicate = b'{"format":"mailroom-recovery-authority-1",' \
                    b'"format":"mailroom-recovery-authority-1","vault":"x",' \
                    b'"stream":"y","revision":0,"purged":[]}'
        path = self.root / "dup.json"
        path.write_bytes(duplicate)
        self.assert_rejected("duplicate JSON key",
                             authority=path, asha=file_digest(path))
        document = json.loads(self.authority_path.read_bytes())
        document["purged"] = list(reversed(document["purged"]))
        path, digest = self.write("unsorted.json", document)
        self.assert_rejected("sorted", authority=path, asha=digest)

    def test_restore_rejects_existing_target_including_symlink(self):
        self.target.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            recovery.restore(self.checkpoint, self.csha, self.authority_path,
                             self.asha, 0, self.target)
        self.assertEqual(self.target.read_bytes(), b"keep")
        dangling = self.out / "dangling.sqlite"
        dangling.symlink_to(self.root / "no-such-target")
        with self.assertRaises(FileExistsError):
            recovery.restore(self.checkpoint, self.csha, self.authority_path,
                             self.asha, 0, dangling)
        self.assertFalse((self.root / "no-such-target").exists())


class RestoreTimelineTests(RecoveryCase):
    """The complete documented timeline using the synthetic fixtures."""

    def build(self):
        db = self.db
        vault.init(FIX / "batch1", db)
        recovery.enable(db)
        vault.retention_plan(db, "RECOVERY-OLD", "2026-11-02T12:00:00Z")
        vault.retention_apply(db, "RECOVERY-OLD")
        review.review_open(db, FIX / "spec-m.json")
        review.review_open(db, FIX / "spec-k.json")
        package_m = self.root / "ext-m.json"
        review.review_export(db, "RECOVERY-M", package_m)
        feedback = self.root / "feedback-m.json"
        feedback.write_bytes(canonical({
            "review_id": "RECOVERY-M",
            "package_sha256": json.loads(package_m.read_text())["package_sha256"],
            "return_id": "RETURN-M",
            "annotations": [{"annotation_id": "NOTE-M", "item_id": "M0001",
                             "start": 0, "end": 5,
                             "comment": "Crane bracket quoted by reviewer."}]}))
        receipt = review.review_return(db, "RECOVERY-M", package_m, feedback)
        package_k = self.root / "ext-k.json"
        review.review_export(db, "RECOVERY-K", package_k)
        collection.collection_import(db, FIX / "manifest.json")
        checkpoint = self.root / "C.json"
        checkpoint_result = recovery.checkpoint(db, checkpoint)
        checkpoint_revision = checkpoint_result["revision"]
        vault.retention_plan(db, "RECOVERY-M-PURGE", "2026-11-03T09:30:00Z")
        vault.retention_apply(db, "RECOVERY-M-PURGE")
        vault.hold_add(db, "RECOVERY-HOLD", "<never@example.invalid>")
        vault.retention_plan(db, "RECOVERY-LATER", "2026-12-01T00:00:00Z")
        vault.ingest(FIX / "later", db)
        authority = self.root / "A.json"
        authority_result = recovery.authority(db, authority)
        return (checkpoint, checkpoint_result, checkpoint_revision,
                authority, authority_result, package_m, receipt, package_k)

    def test_full_timeline(self):
        (checkpoint, checkpoint_result, checkpoint_revision, authority,
         authority_result, package_m, receipt, package_k) = self.build()
        self.assertEqual(checkpoint_revision, 6)
        self.assertEqual(authority_result["revision"], 11)
        self.assertEqual(authority_result["purged_count"], 3)

        # Destroy the source vault and every source directory this demo used;
        # restore must rely on the two offline artefacts alone.
        self.db.unlink()
        recovered = self.root / "recovered.sqlite"
        result = recovery.restore(checkpoint, file_digest(checkpoint), authority,
                                  file_digest(authority), 6, recovered)
        self.assertEqual(list(result), ["mode", "vault", "stream", "revision",
                                        "checkpoint_sha256", "authority_sha256",
                                        "authority_revision", "suppressed"])
        self.assertEqual(result["mode"], "recovered")
        self.assertEqual(result["revision"], checkpoint_revision)
        self.assertEqual(result["checkpoint_sha256"], file_digest(checkpoint))
        self.assertEqual(result["authority_sha256"], file_digest(authority))
        self.assertEqual(result["authority_revision"], 11)
        self.assertEqual(result["suppressed"], sorted([M, D]))
        self.assertEqual(recovery.info(recovered), result)
        # vault and stream identity survive; only the mode and provenance differ
        self.assertEqual(result["vault"], checkpoint_result["vault"])
        self.assertEqual(result["stream"], checkpoint_result["stream"])

        # M is a payload-free purged node, its descendant stays connected
        nodes = vault.vault_thread(recovered, D)
        self.assertEqual([(node["id"], node["status"]) for node in nodes],
                         [(M, "purged"), (D, "purged")])
        self.assertEqual(nodes[0]["parent_id"], None)
        self.assertEqual(nodes[1]["parent_id"], M)
        self.assertTrue(all(node["thread_id"] == M for node in nodes))
        self.assertNotIn("subject", nodes[0])
        self.assertNotIn("sender", nodes[0])
        self.assertEqual(vault.vault_search(recovered, "cracked"), [])
        self.assertEqual([row["id"] for row in
                          vault.vault_search(recovered, "bearings")], [K])

        # post-checkpoint business is invisible and never injected
        self.assertEqual(vault.vault_search(recovered, "checkpoint"), [])
        with self.assertRaisesRegex(ValueError, "unknown message ID"):
            vault.vault_thread(recovered, N)
        with self.assertRaisesRegex(ValueError, "unknown plan ID"):
            vault.retention_show(recovered, "RECOVERY-M-PURGE")
        with self.assertRaisesRegex(ValueError, "unknown plan ID"):
            vault.retention_show(recovered, "RECOVERY-LATER")
        with self.assertRaises(vault.RecoveredVault):
            vault.hold_release(recovered, "RECOVERY-HOLD")

        # checkpoint-era facts remain: old receipt, notes and provenance
        self.assertEqual(vault.retention_show(recovered, "RECOVERY-OLD")["receipt"]["purged"],
                         [OLD])
        notes = review.review_notes(recovered, M)
        self.assertEqual(notes["annotations"][0]["comment"],
                         "Crane bracket quoted by reviewer.")
        self.assertEqual(notes["annotations"][0]["annotation_id"], "NOTE-M")
        sources = collection.vault_provenance(recovered, M)["sources"]
        self.assertEqual([(entry["intake_id"], entry["package_id"],
                           entry["value"]) for entry in sources],
                         [("RECOVERY-COLLECT", "PKG-M", 9)])

        # exports: a suppressed source fails the whole batch, an untouched batch
        # still reproduces its registered bytes
        blocked = self.root / "blocked.json"
        with self.assertRaisesRegex(ValueError, "no longer live"):
            review.review_export(recovered, "RECOVERY-M", blocked)
        self.assertFalse(blocked.exists())
        other = self.root / "keep.json"
        exported = review.review_export(recovered, "RECOVERY-K", other)
        self.assertEqual(other.read_bytes(), package_k.read_bytes())
        self.assertEqual(exported["item_count"], 1)

        # No suppressed payload or derived index reached the recovered file or
        # any staging artefact: this is checked on raw bytes, not by querying.
        raw = recovered.read_bytes()
        for marker in (b"cracked bracket on pier seven",
                       b"raw bracket photo bytes",
                       b"Crane inspection report",
                       b"inspector@example.invalid",
                       b"Follow-up reply acknowledges"):
            self.assertNotIn(marker, raw)
        staging = [path for path in self.root.iterdir()
                   if path.name.startswith(".recovery")]
        self.assertEqual(staging, [])

    def test_recovered_rejects_every_write_entry_without_side_effects(self):
        (checkpoint, _result, revision, authority, _a, package_m,
         _receipt, _package_k) = self.build()
        feedback = self.root / "feedback-m.json"
        recovered = self.root / "recovered.sqlite"
        recovery.restore(checkpoint, file_digest(checkpoint), authority,
                         file_digest(authority), revision, recovered)
        before = recovered.read_bytes()
        attempts = (
            lambda: vault.ingest(FIX / "later", recovered),
            lambda: vault.hold_add(recovered, "RECOVERY-HOLD", "<never@example.invalid>"),
            lambda: vault.hold_release(recovered, "RECOVERY-OLD", ),
            lambda: vault.retention_plan(recovered, "RECOVERY-OLD",
                                         "2026-11-02T12:00:00Z"),
            lambda: vault.retention_apply(recovered, "RECOVERY-OLD"),
            lambda: review.review_open(recovered, FIX / "spec-k.json"),
            lambda: review.review_return(recovered, "RECOVERY-M", package_m, feedback),
            lambda: collection.collection_import(recovered, FIX / "manifest.json"),
            # a true replay of a former success is refused before any input is
            # read, so a missing file still yields the read-only verdict
            lambda: vault.ingest(FIX / "does-not-exist", recovered),
            lambda: review.review_open(recovered, self.root / "absent-spec.json"),
            lambda: collection.collection_import(recovered, self.root / "absent.json"),
            lambda: recovery.enable(recovered),
            lambda: recovery.checkpoint(recovered, self.root / "x.json"),
            lambda: recovery.authority(recovered, self.root / "y.json"),
        )
        for attempt in attempts:
            with self.assertRaises(vault.RecoveredVault):
                attempt()
        self.assertFalse((self.root / "x.json").exists())
        self.assertFalse((self.root / "y.json").exists())
        # read-only commands still work and never rewrite the database
        self.assertEqual(vault.retention_show(recovered, "RECOVERY-OLD")["receipt"],
                         {"vault": vault._vault_id(sqlite3.connect(recovered)),
                          "plan_id": "RECOVERY-OLD", "purged": [OLD],
                          "already_purged": []})
        vault.vault_search(recovered, "bearings")
        vault.vault_thread(recovered, K)
        review.review_notes(recovered, M)
        collection.vault_provenance(recovered, M)
        collection.collection_show(recovered, "RECOVERY-COLLECT")
        recovery.info(recovered)
        self.assertEqual(recovered.read_bytes(), before)

    def test_cli_restore_and_recovered_rejections(self):
        (checkpoint, _r, revision, authority, _a, _pkg, _rec,
         _package_k) = self.build()
        recovered = self.root / "recovered.sqlite"
        code, out, err = self.run_cli(
            "recovery-restore", "--checkpoint", str(checkpoint),
            "--checkpoint-sha256", file_digest(checkpoint),
            "--authority", str(authority),
            "--authority-sha256", file_digest(authority),
            "--min-revision", str(revision), "--db", str(recovered))
        self.assertEqual((code, err), (0, ""))
        payload = json.loads(out)
        self.assertEqual(payload["mode"], "recovered")
        self.assertEqual(payload["suppressed"], sorted([M, D]))
        code, out, err = self.run_cli("recovery-info", "--db", str(recovered))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), payload)
        for argv in (("vault-ingest", "--source", str(FIX / "later"), "--db", str(recovered)),
                     ("hold-add", "--db", str(recovered), "--hold-id", "H9",
                      "--anchor", A),
                     ("retention-apply", "--db", str(recovered),
                      "--plan-id", "RECOVERY-OLD"),
                     ("recovery-enable", "--db", str(recovered)),
                     ("recovery-checkpoint", "--db", str(recovered),
                      "--output", str(self.root / "nope.json")),
                     ("recovery-authority", "--db", str(recovered),
                      "--output", str(self.root / "nope2.json"))):
            code, out, err = self.run_cli(*argv)
            self.assertEqual(code, 2, argv)
            self.assertEqual(out, "")
            self.assertIn("recovered vault is read-only", err)
        # invalid trusted hash exits 2 and leaves no target
        code, out, err = self.run_cli(
            "recovery-restore", "--checkpoint", str(checkpoint),
            "--checkpoint-sha256", "0" * 64,
            "--authority", str(authority),
            "--authority-sha256", file_digest(authority),
            "--min-revision", "0", "--db", str(self.root / "never.sqlite"))
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "never.sqlite").exists())


class RestoreEdgeTests(RecoveryCase):
    def test_suppressed_payload_is_never_staged_on_disk(self):
        # Distinctive marker used only in the source payload; after suppression
        # the bytes must not appear in the target, any temp database or journal.
        marker = "ZQUNIQUESUPPRESSEDPAYLOAD"
        folder = self.batch("marker", ((R, None, f"{marker} live body"),))
        vault.init(folder, self.db)
        recovery.enable(self.db)
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P")
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        out = self.root / "staging"
        out.mkdir()
        target = out / "copy.sqlite"
        result = recovery.restore(checkpoint, file_digest(checkpoint), authority,
                                  file_digest(authority), 2, target)
        self.assertEqual(result["suppressed"], [R])
        artifacts = [path for path in out.iterdir()] + \
            [path for path in self.root.iterdir()
             if path.name.startswith(".recovery")]
        self.assertEqual([path.name for path in artifacts], [target.name])
        for path in artifacts:
            self.assertNotIn(marker.encode(), path.read_bytes())
        # the live payload is intact in the checkpoint, which is legitimately
        # a pre-purge backup and outside the suppression boundary
        self.assertIn(marker.encode(), checkpoint.read_bytes())

    def test_empty_purged_and_empty_suppressed(self):
        self.init()
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        recovered = self.root / "copy.sqlite"
        result = recovery.restore(checkpoint, file_digest(checkpoint), authority,
                                  file_digest(authority), 0, recovered)
        self.assertEqual(result["suppressed"], [])
        self.assertEqual(json.loads((authority).read_bytes())["purged"], [])
        self.assertEqual([row["id"] for row in
                          vault.vault_search(recovered, "ledger")], [R])

    def test_future_authority_identities_are_not_injected(self):
        self.init(((R, None, "ledger body"),))
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        vault.ingest(self.batch("next", ((N, None, "brand new"),)), self.db)
        vault.retention_plan(self.db, "P", "2026-12-01T00:00:00Z")
        vault.retention_apply(self.db, "P")
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        document = json.loads(authority.read_bytes())
        self.assertEqual([entry["message_id"] for entry in document["purged"]],
                         sorted([R, N]))
        recovered = self.root / "copy.sqlite"
        result = recovery.restore(checkpoint, file_digest(checkpoint), authority,
                                  file_digest(authority), 1, recovered)
        self.assertEqual(result["suppressed"], [R])
        self.assertEqual(result["authority_revision"], 3)
        with self.assertRaisesRegex(ValueError, "unknown message ID"):
            vault.vault_thread(recovered, N)
        self.assertEqual(vault.vault_thread(recovered, R)[0]["status"], "purged")

    def test_failure_injection_leaves_no_outputs_or_staging(self):
        self.init()
        vault.retention_plan(self.db, "P", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P")
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        csha, asha = file_digest(checkpoint), file_digest(authority)
        out = self.root / "staging"
        out.mkdir()
        target = out / "copy.sqlite"
        real_connect = sqlite3.connect
        for hook in ("INSERT INTO vault_recovery_state",
                     'INSERT INTO "vault_messages"',
                     'INSERT INTO "vault_attachments"',
                     'INSERT INTO "vault_meta"',
                     'INSERT INTO "vault_receipts"',
                     'INSERT INTO "vault_review_receipts"'):
            class CrashConnection(sqlite3.Connection):
                def execute(self, sql, *args, **kwargs):
                    if isinstance(sql, str) and sql.startswith(hook):
                        raise sqlite3.OperationalError("injected crash")
                    return super().execute(sql, *args, **kwargs)

                def executemany(self, sql, *args, **kwargs):
                    if isinstance(sql, str) and sql.startswith(hook):
                        raise sqlite3.OperationalError("injected crash")
                    return super().executemany(sql, *args, **kwargs)

            with mock.patch("sqlite3.connect",
                            side_effect=lambda *a, **k: real_connect(
                                *a, factory=CrashConnection, **k)):
                with self.assertRaises(sqlite3.OperationalError):
                    recovery.restore(checkpoint, csha, authority, asha, 1, target)
            self.assertFalse(target.exists())
            self.assertEqual(sorted(path.name for path in out.iterdir()), [])
        # the checkpoint and authority themselves are untouched
        self.assertEqual(file_digest(checkpoint), csha)
        self.assertEqual(file_digest(authority), asha)

    def test_source_business_after_checkpoint_differs_in_revision(self):
        self.init(((R, None, "ledger body"),))
        checkpoint = self.root / "c.json"
        recovery.checkpoint(self.db, checkpoint)
        before = self.info()["revision"]
        vault.hold_add(self.db, "H", A)
        self.assertEqual(self.info()["revision"], before + 1)
        # a replay of the same successful hold add does not move the watermark
        vault.hold_add(self.db, "H", A)
        self.assertEqual(self.info()["revision"], before + 1)
        authority = self.root / "a.json"
        recovery.authority(self.db, authority)
        self.assertEqual(json.loads(authority.read_bytes())["revision"], before + 1)


if __name__ == "__main__":
    unittest.main()
