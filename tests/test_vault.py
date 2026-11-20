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
from mailroom import cli, vault
from mailroom.archive import build, search as v1_search, thread as v1_thread

R = "<r@example.invalid>"
P = "<p@example.invalid>"
A = "<a@example.invalid>"


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


class VaultCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"

    def batch(self, name):
        folder = self.root / name
        folder.mkdir()
        return folder

    def query(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def status_map(self):
        return dict(self.query("SELECT id, status FROM vault_messages"))


class IngestTests(VaultCase):
    def test_init_classifies_and_sorts_output(self):
        folder = self.batch("b1")
        write_eml(folder, "z.eml", "<z@x>", date="Tue, 03 Nov 2026 09:00:00 +0000")
        write_eml(folder, "a.eml", "<a@x>", date="Tue, 03 Nov 2026 08:00:00 +0000")
        result = vault.init(folder, self.db)
        self.assertEqual(result["inserted"], ["<a@x>", "<z@x>"])
        self.assertEqual(result["unchanged_live"], [])
        self.assertEqual(result["ignored_purged"], [])
        self.assertTrue(result["vault"])
        self.assertEqual(self.query("SELECT value FROM vault_meta WHERE key='format'"),
                         [("mailroom-vault",)])

    def test_ingest_redelivery_of_live_is_unchanged(self):
        folder = self.batch("b1")
        first = write_eml(folder, "m.eml", "<m@x>", body="original")
        vault.init(folder, self.db)
        folder2 = self.batch("b2")
        folder2.joinpath("m.eml").write_bytes(first.read_bytes())
        write_eml(folder2, "n.eml", "<n@x>", date="Tue, 03 Nov 2026 10:00:00 +0000")
        result = vault.ingest(folder2, self.db)
        self.assertEqual(result, {"inserted": ["<n@x>"], "unchanged_live": ["<m@x>"],
                                  "ignored_purged": []})
        self.assertEqual(sorted(self.status_map()), ["<m@x>", "<n@x>"])

    def test_conflicting_redelivery_rolls_back_whole_batch(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", body="original")
        vault.init(folder, self.db)
        folder2 = self.batch("b2")
        write_eml(folder2, "m.eml", "<m@x>", body="tampered")  # same ID, new bytes
        write_eml(folder2, "n.eml", "<n@x>")
        with self.assertRaisesRegex(ValueError, "conflicting redelivery"):
            vault.ingest(folder2, self.db)
        self.assertEqual(self.status_map(), {"<m@x>": "live"})
        body, = self.query("SELECT body FROM vault_messages WHERE id='<m@x>'")[0]
        self.assertEqual(body, "original\n")

    def test_cross_batch_reply_cycle_rolls_back_whole_batch(self):
        folder = self.batch("b1")
        write_eml(folder, "x.eml", "<x@x>", parent="<y@x>")  # Y missing for now
        vault.init(folder, self.db)
        folder2 = self.batch("b2")
        write_eml(folder2, "y.eml", "<y@x>", parent="<x@x>")  # completes a cycle
        write_eml(folder2, "n.eml", "<n@x>")
        with self.assertRaisesRegex(ValueError, "reply cycle"):
            vault.ingest(folder2, self.db)
        self.assertEqual(self.status_map(), {"<x@x>": "live"})

    def test_duplicate_message_id_within_batch_rejected(self):
        folder = self.batch("b1")
        write_eml(folder, "1.eml", "<m@x>")
        write_eml(folder, "2.eml", "<m@x>")
        with self.assertRaisesRegex(ValueError, "duplicate Message-ID"):
            vault.init(folder, self.db)
        self.assertFalse(self.db.exists())

    def test_late_parent_reroots_existing_replies(self):
        folder = self.batch("b1")
        write_eml(folder, "r.eml", R, parent=P, date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {R: P})
        folder2 = self.batch("b2")
        write_eml(folder2, "p.eml", P, parent=A, date="Sun, 01 Nov 2026 09:00:00 +0000")
        vault.ingest(folder2, self.db)
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {R: A, P: A})
        folder3 = self.batch("b3")
        write_eml(folder3, "a.eml", A, date="Sat, 31 Oct 2026 09:00:00 +0000")
        vault.ingest(folder3, self.db)
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {R: A, P: A, A: A})

    def test_purged_nodes_still_join_chains_and_cycles(self):
        folder = self.batch("b1")
        write_eml(folder, "x.eml", "<x@x>", parent="<m@x>",
                  date="Sun, 01 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P0", "2026-11-02T00:00:00Z")
        self.assertEqual(vault.retention_apply(self.db, "P0")["purged"], ["<x@x>"])
        # a cycle closing through the purged identity fails the whole batch
        folder2 = self.batch("b2")
        write_eml(folder2, "m.eml", "<m@x>", parent="<x@x>")
        write_eml(folder2, "other.eml", "<other@x>")
        with self.assertRaisesRegex(ValueError, "reply cycle"):
            vault.ingest(folder2, self.db)
        self.assertEqual(self.status_map(), {"<x@x>": "purged"})
        # a legitimate late parent re-roots the purged identity and new replies
        folder3 = self.batch("b3")
        write_eml(folder3, "m.eml", "<m@x>", date="Sat, 31 Oct 2026 08:00:00 +0000")
        write_eml(folder3, "n.eml", "<n@x>", parent="<x@x>",
                  date="Tue, 03 Nov 2026 08:00:00 +0000")
        result = vault.ingest(folder3, self.db)
        self.assertEqual(result["inserted"], ["<m@x>", "<n@x>"])
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {"<x@x>": "<m@x>", "<m@x>": "<m@x>", "<n@x>": "<m@x>"})

    def test_init_refuses_existing_target_and_cleans_temp(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        with self.assertRaises(FileExistsError):
            vault.init(folder, self.db)
        link = self.root / "link.sqlite"
        link.symlink_to(self.db)
        with self.assertRaises(FileExistsError):
            vault.init(folder, link)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         ["b1", "link.sqlite", "vault.sqlite"])

    def test_vault_works_after_source_removal(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", body="commonword")
        vault.init(folder, self.db)
        import shutil
        shutil.rmtree(folder)  # historical sources are never re-read
        folder2 = self.batch("b2")
        write_eml(folder2, "n.eml", "<n@x>", parent="<m@x>", body="commonword",
                  date="Tue, 03 Nov 2026 09:00:00 +0000")
        self.assertEqual(vault.ingest(folder2, self.db)["inserted"], ["<n@x>"])
        self.assertEqual(len(vault.vault_search(self.db, "commonword")), 2)
        self.assertEqual(len(vault.vault_thread(self.db, "<n@x>")), 2)

    def test_mutations_require_existing_vault(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        missing = self.root / "missing.sqlite"
        for call in (lambda: vault.ingest(folder, missing),
                     lambda: vault.hold_add(missing, "H", A),
                     lambda: vault.hold_release(missing, "H"),
                     lambda: vault.retention_plan(missing, "P", "2026-11-04T00:00:00Z"),
                     lambda: vault.retention_apply(missing, "P")):
            with self.assertRaisesRegex(ValueError, "vault does not exist"):
                call()
        self.assertFalse(missing.exists())


class HoldTests(VaultCase):
    def init_one(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", parent=A)  # anchor stays external
        vault.init(folder, self.db)

    def test_hold_registration_rules(self):
        self.init_one()
        self.assertEqual(vault.hold_add(self.db, "H1", A),
                         {"hold_id": "H1", "anchor": A, "state": "active"})
        self.assertEqual(vault.hold_add(self.db, "H1", A)["state"], "active")  # retry
        with self.assertRaisesRegex(ValueError, "another anchor"):
            vault.hold_add(self.db, "H1", "<b@x>")
        self.assertEqual(vault.hold_release(self.db, "H1")["state"], "released")
        self.assertEqual(vault.hold_release(self.db, "H1")["state"], "released")  # repeat
        with self.assertRaisesRegex(ValueError, "already released"):
            vault.hold_add(self.db, "H1", A)
        with self.assertRaisesRegex(ValueError, "unknown hold ID"):
            vault.hold_release(self.db, "H2")
        self.assertEqual(self.query("SELECT hold_id, state FROM vault_holds"),
                         [("H1", "released")])

    def test_hold_and_plan_id_syntax_and_namespaces(self):
        self.init_one()
        for bad in ("", ".h", "-h", "_h", "h h", "h/x", "h" * 65, "é"):
            with self.assertRaisesRegex(ValueError, "must match", msg=bad):
                vault.hold_add(self.db, bad, A)
            with self.assertRaisesRegex(ValueError, "must match", msg=bad):
                vault.retention_plan(self.db, bad, "2026-11-04T00:00:00Z")
        vault.hold_add(self.db, "h" * 64, A)  # 64 chars is legal
        with self.assertRaisesRegex(ValueError, "hold anchor"):
            vault.hold_add(self.db, "H9", "not-an-id")
        # hold and plan IDs live in independent namespaces and are case-sensitive
        vault.hold_add(self.db, "Same", A)
        vault.retention_plan(self.db, "Same", "2026-11-04T00:00:00Z")
        vault.hold_add(self.db, "same", A)
        self.assertEqual([r[0] for r in self.query(
            "SELECT hold_id FROM vault_holds ORDER BY hold_id")], ["Same", "h" * 64, "same"])

    def test_overlapping_holds_release_one_by_one(self):
        self.init_one()  # <m@x> hangs off external anchor A
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual([c["id"] for c in plan["candidates"]], ["<m@x>"])
        self.assertEqual(plan["held"], [])
        vault.hold_add(self.db, "H1", A)  # external parent ID matches the anchor
        vault.hold_add(self.db, "H2", A)  # union coverage from two holds
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(self.db, "P1")
        self.assertEqual(ctx.exception.blocked, [{"id": "<m@x>", "holds": ["H1", "H2"]}])
        vault.hold_release(self.db, "H1")
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(self.db, "P1")
        self.assertEqual(ctx.exception.blocked, [{"id": "<m@x>", "holds": ["H2"]}])
        self.assertEqual(self.status_map(), {"<m@x>": "live"})  # no partial purge
        vault.hold_release(self.db, "H2")
        self.assertEqual(vault.retention_apply(self.db, "P1")["purged"], ["<m@x>"])

    def test_held_items_never_join_purge(self):
        self.init_one()
        vault.hold_add(self.db, "H1", A)
        vault.hold_add(self.db, "H2", A)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual(plan["candidates"], [])
        self.assertEqual([h["id"] for h in plan["held"]], ["<m@x>"])
        self.assertEqual(plan["held"][0]["holds"], ["H1", "H2"])
        vault.hold_release(self.db, "H1")
        vault.hold_release(self.db, "H2")
        receipt = vault.retention_apply(self.db, "P1")
        self.assertEqual(receipt["purged"], [])  # held items never join the purge
        self.assertEqual(self.status_map(), {"<m@x>": "live"})

    def test_hold_may_precede_anchor_arrival(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        vault.hold_add(self.db, "H1", "<future@x>")  # anchor not archived yet
        folder2 = self.batch("b2")
        write_eml(folder2, "f.eml", "<future@x>", date="Tue, 03 Nov 2026 07:00:00 +0000")
        vault.ingest(folder2, self.db)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual([h["id"] for h in plan["held"]], ["<future@x>"])
        self.assertEqual(plan["held"][0]["holds"], ["H1"])
        self.assertEqual([c["id"] for c in plan["candidates"]], ["<m@x>"])

    def test_hold_may_anchor_on_purged_message(self):
        folder = self.batch("b1")
        write_eml(folder, "root.eml", "<root@x>", date="Sun, 01 Nov 2026 08:00:00 +0000")
        write_eml(folder, "kid.eml", "<kid@x>", parent="<root@x>",
                  date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P0", "2026-11-02T00:00:00Z")
        self.assertEqual(vault.retention_apply(self.db, "P0")["purged"], ["<root@x>"])
        vault.hold_add(self.db, "H1", "<root@x>")  # anchor already purged: legal
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual([h["id"] for h in plan["held"]], ["<kid@x>"])
        self.assertEqual(plan["held"][0]["holds"], ["H1"])


class PlanTests(VaultCase):
    def test_before_time_validation_and_normalization(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        for bad in ("2026-11-04", "2026-11-04T00:00", "2026-11-04T00:00:00",
                    "2026-11-04 00:00:00Z", "2026-11-04T00:00:00.1234567Z",
                    "2026-13-04T00:00:00Z", "2026-11-04T00:00:00+25:00", "", "soon"):
            with self.assertRaisesRegex(ValueError, "ISO 8601", msg=bad):
                vault.retention_plan(self.db, "PBAD", bad)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T01:00:00.5+01:00")
        self.assertEqual(plan["before"], "2026-11-04T00:00:00.500000+00:00")

    def test_plan_retry_same_instant_returns_original(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T01:00:00+01:00")
        self.assertEqual(plan["before"], "2026-11-04T00:00:00+00:00")
        # equivalent instant in another offset returns the frozen first plan
        again = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual(again, plan)
        with self.assertRaisesRegex(ValueError, "different cutoff"):
            vault.retention_plan(self.db, "P1", "2026-11-04T00:00:01Z")

    def test_plan_is_frozen_despite_later_changes(self):
        folder = self.batch("b1")
        path = write_eml(folder, "m.eml", "<m@x>", date="Tue, 03 Nov 2026 08:00:00 +0000",
                         body="secret payload")
        vault.init(folder, self.db)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(plan["candidates"], [{"id": "<m@x>", "sha256": sha}])
        self.assertEqual(set(plan), {"vault", "plan_id", "before", "candidates", "held"})
        folder2 = self.batch("b2")
        write_eml(folder2, "n.eml", "<n@x>", date="Tue, 03 Nov 2026 09:00:00 +0000")
        vault.ingest(folder2, self.db)
        vault.hold_add(self.db, "H1", "<m@x>")
        shown = vault.retention_show(self.db, "P1")
        self.assertEqual(shown["plan"], plan)  # not recomputed from current state
        self.assertIsNone(shown["receipt"])
        # retry with the same instant still returns the first saved plan
        self.assertEqual(vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z"), plan)
        stored, = self.query("SELECT document FROM vault_plans WHERE plan_id='P1'")[0]
        self.assertNotIn("secret payload", stored)  # plans are no payload backup

    def test_empty_plan_is_legal(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        plan = vault.retention_plan(self.db, "EMPTY", "2026-11-01T00:00:00Z")
        self.assertEqual(plan["candidates"], [])
        self.assertEqual(plan["held"], [])
        receipt = vault.retention_apply(self.db, "EMPTY")
        self.assertEqual(receipt["purged"], [])
        self.assertEqual(receipt["already_purged"], [])
        self.assertEqual(vault.retention_apply(self.db, "EMPTY"), receipt)

    def test_cutoff_equality_and_overlapping_plans(self):
        folder = self.batch("b1")
        write_eml(folder, "m1.eml", "<m1@x>", date="Sun, 01 Nov 2026 09:00:00 +0000")
        write_eml(folder, "m2.eml", "<m2@x>", date="Mon, 02 Nov 2026 09:00:00 +0000")
        write_eml(folder, "m3.eml", "<m3@x>", date="Wed, 04 Nov 2026 00:00:00 +0000")
        vault.init(folder, self.db)
        early = vault.retention_plan(self.db, "PA", "2026-11-02T00:00:00Z")
        self.assertEqual([c["id"] for c in early["candidates"]], ["<m1@x>"])
        late = vault.retention_plan(self.db, "PB", "2026-11-04T00:00:00Z")
        # sent_at exactly at the cutoff is not due
        self.assertEqual([c["id"] for c in late["candidates"]], ["<m1@x>", "<m2@x>"])
        self.assertEqual(vault.retention_apply(self.db, "PA")["purged"], ["<m1@x>"])
        receipt = vault.retention_apply(self.db, "PB")
        self.assertEqual(receipt["purged"], ["<m2@x>"])
        self.assertEqual(receipt["already_purged"], ["<m1@x>"])
        self.assertEqual(self.status_map()["<m3@x>"], "live")

    def test_unknown_plan_rejected(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        with self.assertRaisesRegex(ValueError, "unknown plan ID"):
            vault.retention_show(self.db, "NOPE")
        with self.assertRaisesRegex(ValueError, "unknown plan ID"):
            vault.retention_apply(self.db, "NOPE")


class ApplyTests(VaultCase):
    def test_late_parent_blocks_then_purges_only_original_candidates(self):
        # R replies to missing P; hold anchor A does not cover R yet.
        folder = self.batch("b1")
        write_eml(folder, "r.eml", R, parent=P, date="Tue, 03 Nov 2026 08:00:00 +0000",
                  subject="Reply notes", body="reply ledger")
        vault.init(folder, self.db)
        vault.hold_add(self.db, "H1", A)
        plan = vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual([c["id"] for c in plan["candidates"]], [R])
        self.assertEqual(plan["held"], [])
        # P arrives late and replies to A: R joins the hold via the completed chain.
        folder2 = self.batch("b2")
        write_eml(folder2, "p.eml", P, parent=A, date="Sun, 01 Nov 2026 09:00:00 +0000",
                  subject="Parent notes", body="parent ledger")
        self.assertEqual(vault.ingest(folder2, self.db)["inserted"], [P])
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(self.db, "P1")
        self.assertEqual(ctx.exception.blocked, [{"id": R, "holds": ["H1"]}])
        # blocked apply left no partial purge and no receipt
        self.assertEqual(self.status_map(), {R: "live", P: "live"})
        self.assertEqual(self.query("SELECT * FROM vault_receipts"), [])
        self.assertEqual(len(vault.vault_search(self.db, "ledger")), 2)
        # plan is still viewable and retryable once the hold is released
        self.assertEqual(vault.retention_show(self.db, "P1")["plan"], plan)
        vault.hold_release(self.db, "H1")
        receipt = vault.retention_apply(self.db, "P1")
        self.assertEqual(receipt["purged"], [R])
        self.assertEqual(receipt["already_purged"], [])
        self.assertEqual(receipt["plan_id"], "P1")
        self.assertEqual(receipt["vault"], plan["vault"])
        # late P is equally old but was never in the frozen plan
        self.assertEqual(self.status_map(), {R: "purged", P: "live"})
        row = self.query("SELECT subject, sender, body, source_bytes, sent_at, parent_id,"
                         " source_sha256 FROM vault_messages WHERE id=?", (R,))[0]
        self.assertEqual(row[:4], (None, None, None, None))
        self.assertEqual(row[4], "2026-11-03T08:00:00+00:00")
        self.assertEqual(row[5], P)
        self.assertTrue(row[6])
        self.assertEqual(self.query("SELECT * FROM vault_attachments"), [])
        self.assertEqual(self.query("SELECT * FROM vault_search WHERE message_id=?", (R,)), [])
        self.assertEqual([r["id"] for r in vault.vault_search(self.db, "ledger")], [P])

    def test_receipt_replay_ignores_later_holds_and_ingests(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        receipt = vault.retention_apply(self.db, "P1")
        self.assertEqual(receipt["purged"], ["<m@x>"])
        vault.hold_add(self.db, "H9", "<m@x>")  # new hold over the purged message
        folder2 = self.batch("b2")
        write_eml(folder2, "n.eml", "<n@x>", date="Tue, 03 Nov 2026 07:00:00 +0000")
        vault.ingest(folder2, self.db)
        self.assertEqual(vault.retention_apply(self.db, "P1"), receipt)  # first receipt
        self.assertEqual(len(self.query("SELECT * FROM vault_receipts")), 1)
        shown = vault.retention_show(self.db, "P1")
        self.assertEqual(shown["receipt"], receipt)
        stored, = self.query("SELECT document FROM vault_receipts WHERE plan_id='P1'")[0]
        self.assertNotIn("body text", stored)  # receipts are no payload backup

    def test_purged_node_keeps_thread_connected(self):
        folder = self.batch("b1")
        write_eml(folder, "f.eml", "<f@x>", parent="<g@x>",
                  date="Sun, 01 Nov 2026 08:00:00 +0000")
        write_eml(folder, "e.eml", "<e@x>", parent="<f@x>",
                  date="Mon, 02 Nov 2026 08:00:00 +0000")
        write_eml(folder, "g.eml", "<g@x>", date="Tue, 03 Nov 2026 08:00:00 +0000")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P1", "2026-11-01T12:00:00Z")  # only <f@x> due
        self.assertEqual(vault.retention_apply(self.db, "P1")["purged"], ["<f@x>"])
        nodes = vault.vault_thread(self.db, "<e@x>")
        self.assertEqual([n["id"] for n in nodes], ["<f@x>", "<e@x>", "<g@x>"])
        self.assertTrue(all(n["thread_id"] == "<g@x>" for n in nodes))
        self.assertEqual(nodes[0]["status"], "purged")
        self.assertEqual(nodes[0]["parent_id"], "<g@x>")
        self.assertNotIn("subject", nodes[0])
        self.assertNotIn("sender", nodes[0])
        self.assertEqual(nodes[1]["parent_id"], "<f@x>")  # child not disconnected
        self.assertEqual(nodes[1]["subject"], "Note")
        self.assertEqual(nodes[2]["status"], "live")

    def test_purged_redelivery_only_confirms_identity(self):
        folder = self.batch("b1")
        original = write_eml(folder, "m.eml", "<m@x>", body="secret payload")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P1")
        folder2 = self.batch("b2")
        folder2.joinpath("m.eml").write_bytes(original.read_bytes())  # identical bytes
        result = vault.ingest(folder2, self.db)
        self.assertEqual(result, {"inserted": [], "unchanged_live": [],
                                  "ignored_purged": ["<m@x>"]})
        row = self.query("SELECT status, source_bytes, subject FROM vault_messages"
                         " WHERE id='<m@x>'")[0]
        self.assertEqual(row, ("purged", None, None))  # payload not restored
        self.assertEqual(vault.vault_search(self.db, "secret"), [])

    def test_failed_apply_leaves_content_fts_and_receipt_consistent(self):
        folder = self.batch("b1")
        write_eml(folder, "m1.eml", "<m1@x>", body="commonword one")
        write_eml(folder, "m2.eml", "<m2@x>", body="commonword two",
                  date="Tue, 03 Nov 2026 09:00:00 +0000")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.lstrip().upper().startswith(
                        "INSERT INTO VAULT_RECEIPTS"):
                    raise sqlite3.OperationalError("injected crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect",
                        side_effect=lambda *a, **k: real_connect(*a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                vault.retention_apply(self.db, "P1")
        # after the crash the last complete state is readable: both messages live
        self.assertEqual(self.status_map(), {"<m1@x>": "live", "<m2@x>": "live"})
        self.assertEqual(self.query("SELECT count(*) FROM vault_messages "
                                    "WHERE subject IS NULL OR body IS NULL "
                                    "OR source_bytes IS NULL"), [(0,)])
        self.assertEqual([r[0] for r in self.query(
            "SELECT message_id FROM vault_search ORDER BY message_id")], ["<m1@x>", "<m2@x>"])
        self.assertEqual([r["id"] for r in vault.vault_search(self.db, "commonword")],
                         ["<m1@x>", "<m2@x>"])
        self.assertEqual(self.query("SELECT * FROM vault_receipts"), [])
        # retry now commits payload removal, FTS update and receipt together
        receipt = vault.retention_apply(self.db, "P1")
        self.assertEqual(receipt["purged"], ["<m1@x>", "<m2@x>"])
        self.assertEqual(self.status_map(), {"<m1@x>": "purged", "<m2@x>": "purged"})
        self.assertEqual(self.query("SELECT * FROM vault_search"), [])
        self.assertEqual(vault.vault_search(self.db, "commonword"), [])
        self.assertEqual(len(self.query("SELECT * FROM vault_receipts")), 1)
        self.assertEqual(vault.retention_apply(self.db, "P1"), receipt)

    def test_failed_ingest_leaves_vault_unchanged(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", body="commonword")
        vault.init(folder, self.db)
        folder2 = self.batch("b2")
        write_eml(folder2, "n.eml", "<n@x>", body="commonword")
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.lstrip().upper().startswith(
                        "UPDATE VAULT_MESSAGES SET THREAD_ID"):
                    raise sqlite3.OperationalError("injected crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect",
                        side_effect=lambda *a, **k: real_connect(*a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                vault.ingest(folder2, self.db)
        self.assertEqual(self.status_map(), {"<m@x>": "live"})
        self.assertEqual([r[0] for r in self.query("SELECT message_id FROM vault_search")],
                         ["<m@x>"])
        self.assertEqual([r["id"] for r in vault.vault_search(self.db, "commonword")],
                         ["<m@x>"])


class QueryTests(VaultCase):
    def test_search_limits_and_validation(self):
        folder = self.batch("b1")
        for number in range(105):
            write_eml(folder, f"{number:03}.eml", f"<m{number}@x>",
                      date=f"Tue, 03 Nov 2026 08:{number % 60:02d}:00 +0000",
                      body="commonword item")
        vault.init(folder, self.db)
        self.assertEqual(len(vault.vault_search(self.db, "commonword")), 100)
        with self.assertRaisesRegex(ValueError, "at most 200"):
            vault.vault_search(self.db, "x" * 201)
        with self.assertRaisesRegex(ValueError, "letter or digit"):
            vault.vault_search(self.db, "!!!")
        self.assertEqual(vault.vault_search(self.db, "commonword absent"), [])

    def test_thread_unknown_id_rejected(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        with self.assertRaisesRegex(ValueError, "unknown message ID"):
            vault.vault_thread(self.db, "<nope@x>")

    def test_readonly_commands_do_not_modify_database(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", body="commonword")
        vault.init(folder, self.db)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        digest = hashlib.sha256(self.db.read_bytes()).hexdigest()
        vault.vault_search(self.db, "commonword")
        vault.vault_thread(self.db, "<m@x>")
        vault.retention_show(self.db, "P1")
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), digest)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["b1", "vault.sqlite"])


class FormatSeparationTests(VaultCase):
    def test_v1_database_rejected_by_vault_commands_and_preserved(self):
        v1 = self.root / "v1.sqlite"
        build("fixtures/mail", v1)
        digest = hashlib.sha256(v1.read_bytes()).hexdigest()
        calls = (lambda: vault.vault_search(v1, "harbor"),
                 lambda: vault.vault_thread(v1, "<reply@example.invalid>"),
                 lambda: vault.hold_add(v1, "H", A),
                 lambda: vault.hold_release(v1, "H"),
                 lambda: vault.retention_plan(v1, "P", "2026-11-04T00:00:00Z"),
                 lambda: vault.retention_show(v1, "P"),
                 lambda: vault.retention_apply(v1, "P"),
                 lambda: vault.ingest("fixtures/mail", v1))
        for call in calls:
            with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
                call()
        self.assertEqual(hashlib.sha256(v1.read_bytes()).hexdigest(), digest)
        self.assertEqual(len(v1_search(v1, "harbor")), 2)  # v1 archive still works

    def test_vault_database_rejected_by_v1_commands(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", body="commonword")
        vault.init(folder, self.db)
        with self.assertRaises(sqlite3.Error):
            v1_search(self.db, "commonword")
        with self.assertRaises(sqlite3.Error):
            v1_thread(self.db, "<m@x>")
        self.assertEqual([r["id"] for r in vault.vault_search(self.db, "commonword")],
                         ["<m@x>"])


class CliTests(VaultCase):
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

    def test_success_exit_zero_and_json(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        code, out, _ = self.run_cli("vault-init", "--source", str(folder),
                                    "--db", str(self.db))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["inserted"], ["<m@x>"])
        code, out, _ = self.run_cli("hold-add", "--db", str(self.db),
                                    "--hold-id", "H1", "--anchor", A)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "active")

    def test_blocked_apply_reports_json_on_stderr(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>", parent=A)
        vault.init(folder, self.db)
        vault.hold_add(self.db, "H1", A)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        # move the message into candidates by planning before the hold existed:
        # instead register plan first in a fresh vault
        db2 = self.root / "v2.sqlite"
        vault.init(folder, db2)
        vault.retention_plan(db2, "P1", "2026-11-04T00:00:00Z")
        vault.hold_add(db2, "H1", A)
        code, out, err = self.run_cli("retention-apply", "--db", str(db2),
                                      "--plan-id", "P1")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err), {"error": "held",
                                           "blocked": [{"id": "<m@x>", "holds": ["H1"]}]})
        self.assertEqual(out, "")
        self.assertEqual(self.query("SELECT * FROM vault_receipts"), [])

    def test_invalid_input_exit_two(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m@x>")
        vault.init(folder, self.db)
        code, _, err = self.run_cli("retention-apply", "--db", str(self.db),
                                    "--plan-id", "NOPE")
        self.assertEqual(code, 2)
        self.assertIn("unknown plan ID", err)
        code, _, err = self.run_cli("vault-search", "--db", str(self.root / "v1.sqlite"),
                                    "--query", "x")
        self.assertEqual(code, 2)


class FixtureDemoTests(VaultCase):
    def test_readme_demo_scenario(self):
        db = self.root / "demo.sqlite"
        result = vault.init("fixtures/vault/batch1", db)
        self.assertEqual(result["inserted"], ["<reply-r@example.invalid>"])
        vault.hold_add(db, "LEGAL-1", "<anchor-a@example.invalid>")
        plan = vault.retention_plan(db, "Q1", "2026-11-04T00:00:00Z")
        self.assertEqual([c["id"] for c in plan["candidates"]],
                         ["<reply-r@example.invalid>"])
        self.assertEqual(plan["held"], [])
        result = vault.ingest("fixtures/vault/batch2", db)
        self.assertEqual(result["inserted"], ["<parent-p@example.invalid>"])
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(db, "Q1")
        self.assertEqual(ctx.exception.blocked,
                         [{"id": "<reply-r@example.invalid>", "holds": ["LEGAL-1"]}])
        vault.hold_release(db, "LEGAL-1")
        receipt = vault.retention_apply(db, "Q1")
        self.assertEqual(receipt["purged"], ["<reply-r@example.invalid>"])
        self.assertEqual(receipt["already_purged"], [])
        self.assertEqual(vault.retention_apply(db, "Q1"), receipt)
        nodes = vault.vault_thread(db, "<parent-p@example.invalid>")
        self.assertEqual([(n["id"], n["status"]) for n in nodes],
                         [("<parent-p@example.invalid>", "live"),
                          ("<reply-r@example.invalid>", "purged")])
        self.assertTrue(all(n["thread_id"] == "<anchor-a@example.invalid>" for n in nodes))
        self.assertEqual([r["id"] for r in vault.vault_search(db, "ledger")],
                         ["<parent-p@example.invalid>"])


if __name__ == "__main__":
    unittest.main()
