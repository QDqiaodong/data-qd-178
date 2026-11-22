"""Resumable mboxrd intake: ledger, quarantine, resolve, certify and recovery.

The expected digests in these tests are computed independently from raw byte
slices of the mailbox files (never from values returned by the module under
test), so they catch hashing, boundary and unescaping regressions.
"""
import contextlib
import hashlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mailroom import cli, mbox, recovery, vault
from mailroom.archive import build as v1_build

A = "<anchor-a@example.invalid>"
P = "<parent-p@example.invalid>"
R = "<reply-r@example.invalid>"
CANONICAL = dict(ensure_ascii=False, sort_keys=True,
                 separators=(",", ":"), allow_nan=False)


def write_eml(directory, name, msg_id, parent=None,
              date="Tue, 03 Nov 2026 09:00:00 +0000", subject="Note",
              body="body text", sender="s@example.invalid",
              content_type="text/plain; charset=utf-8"):
    headers = [f"From: {sender}", "To: r@example.invalid", f"Date: {date}",
               f"Message-ID: {msg_id}"]
    if parent is not None:
        headers.append(f"In-Reply-To: {parent}")
    headers += [f"Subject: {subject}", "MIME-Version: 1.0",
               f"Content-Type: {content_type}"]
    path = Path(directory) / name
    path.write_text("\n".join(headers) + "\n\n" + body + "\n")
    return path


def eml_bytes(msg_id, parent=None, body="body text", subject="Note",
              trailing_lf=True):
    headers = ["From: s@example.invalid", "To: r@example.invalid",
               "Date: Tue, 03 Nov 2026 09:00:00 +0000",
               f"Message-ID: {msg_id}"]
    if parent is not None:
        headers.append(f"In-Reply-To: {parent}")
    headers += [f"Subject: {subject}", "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8"]
    raw = ("\n".join(headers) + "\n\n" + body + ("\n" if trailing_lf else ""))
    return raw.encode()


def envelope(tag, rest=b""):
    return f"From {tag} Tue Nov  3 08:00:00 2026\n".encode() + rest


def raw_digest(data):
    return hashlib.sha256(data).hexdigest()


class MboxCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"
        folder = self.root / "seed"
        folder.mkdir()
        write_eml(folder, "a.eml", A)
        vault.init(folder, self.db)

    def path(self, name):
        return self.root / name

    def write_mbox(self, name, chunks):
        path = self.path(name)
        path.write_bytes(b"".join(chunks))
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", ["mail-archive", *argv]), \
                contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def query(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()


class ParsingTests(MboxCase):
    def test_mboxrd_unescaping_and_raw_range_digest(self):
        body = (b"headers: x\n\nline one\n>From quoted\n>>From twice\n"
                b">>>From three\nplain>From kept\n")
        data = envelope("one", body) + envelope("two", b"tail\n")
        path = self.write_mbox("p.mbox", [data])
        boundary = len(envelope("one", body))
        env_end = data.find(b"\n") + 1
        record_sha, decoded, oversize = mbox._decode_record(
            path, 0, env_end, boundary)
        self.assertFalse(oversize)
        self.assertEqual(
            decoded,
            b"headers: x\n\nline one\nFrom quoted\n>From twice\n"
            b">>From three\nplain>From kept\n")
        self.assertEqual(record_sha, raw_digest(data[:boundary]))

    def test_cr_and_no_trailing_lf_are_preserved(self):
        message = eml_bytes("<c@x>", body="crlf\r\nand utf-8 テスト")
        data = envelope("c", message) + envelope("n")
        path = self.write_mbox("c.mbox", [data])
        boundary = len(envelope("c", message))
        sha, decoded, _ = mbox._decode_record(
            path, 0, data.find(b"\n") + 1, boundary)
        self.assertEqual(decoded, message)  # CR kept, no normalization
        self.assertEqual(sha, raw_digest(data[:boundary]))
        # last message may legitimately lack a final LF
        no_lf = envelope("n", eml_bytes("<n@x>", trailing_lf=False))
        path2 = self.write_mbox("n.mbox", [no_lf])
        result = mbox.mbox_scan(self.db, "N", path2, seal=True)
        self.assertEqual(result["records"][0]["status"], "admitted")
        self.assertEqual(result["next_offset"], len(no_lf))

    def test_unescape_across_chunk_boundary(self):
        padding = b"z" * (mbox.CHUNK - 2)
        data = envelope("x", padding + b"\n>From split\n") + envelope("y")
        path = self.write_mbox("x.mbox", [data])
        boundary = len(envelope("x", padding + b"\n>From split\n"))
        _, decoded, _ = mbox._decode_record(
            path, 0, data.find(b"\n") + 1, boundary)
        self.assertTrue(decoded.endswith(b"z\nFrom split\n"))

    def test_oversize_record_is_crossed_completely_and_hashed(self):
        big = b"X" * (mbox.MAX_MESSAGE + 10_000)
        message = (b"From: g@x\nTo: r@x\nDate: Tue, 03 Nov 2026 09:00:00 +0000\n"
                   b"Message-ID: <big@x>\nSubject: Big\nMIME-Version: 1.0\n"
                   b"Content-Type: text/plain; charset=utf-8\n\n" + big + b"\n")
        oversize_record = envelope("big", message)
        good = envelope("after", eml_bytes("<after@x>"))
        data = oversize_record + good
        path = self.write_mbox("big.mbox", [data])
        r = mbox.mbox_scan(self.db, "BIG", path, seal=True)
        self.assertEqual(
            [(x["status"], x.get("reason")) for x in r["records"]],
            [("unresolved", "oversize"), ("admitted", None)])
        gap = r["records"][0]
        self.assertEqual(gap["end"], len(oversize_record))
        self.assertEqual(gap["record_sha256"], raw_digest(oversize_record))
        self.assertEqual(r["records"][1]["start"], gap["end"])
        self.assertEqual(r["records"][-1]["end"], len(data))
        self.assertEqual(
            self.query("SELECT 1 FROM vault_messages WHERE id='<big@x>'"), [])
        self.assertEqual(
            self.query("SELECT 1 FROM vault_attachments WHERE message_id='<big@x>'"), [])
        self.assertEqual(
            self.query("SELECT 1 FROM vault_search WHERE message_id='<big@x>'"), [])

    def test_source_working_set_is_bounded_on_a_multimegabyte_mailbox(self):
        # A mailbox far above the 40 MB directory limit with multi-MB bad
        # records: every raw read stays within one fixed chunk regardless of
        # total size, and scanning still reaches the valid records afterwards.
        first_bad = b"From pad\n" + b"P" * 20_000_000 + b"\n"
        second_bad = b"From giant\n" + b"Q" * 5_000_000 + b"\n"
        tail = (b"From g1\n" + eml_bytes("<gb1@x>")
                + b"From g2\n" + eml_bytes("<gb2@x>"))
        data = first_bad + second_bad + tail
        path = self.write_mbox("huge.mbox", [data])
        self.assertGreater(path.stat().st_size, 25_000_000)
        max_read = {"value": 0}
        real_open = open

        class TrackedFile:
            def __init__(self, stream):
                self.stream = stream

            def read(self, *args):
                chunk = self.stream.read(*args)
                max_read["value"] = max(max_read["value"], len(chunk))
                return chunk

            def seek(self, *args):
                return self.stream.seek(*args)

            def tell(self):
                return self.stream.tell()

            def close(self):
                return self.stream.close()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.stream.close()

        def tracking_open(path, mode="rb", *args, **kwargs):
            stream = real_open(path, mode, *args, **kwargs)
            return TrackedFile(stream) if "b" in mode else stream

        with mock.patch("mailroom.mbox.open", side_effect=tracking_open):
            r = mbox.mbox_scan(self.db, "HUGE", path, seal=True)
        self.assertLessEqual(max_read["value"], mbox.CHUNK)
        self.assertEqual(
            [(x["status"], x.get("reason")) for x in r["records"]],
            [("unresolved", "oversize"), ("unresolved", "oversize"),
             ("admitted", None), ("admitted", None)])
        self.assertEqual(r["records"][-1]["end"], len(data))
        gap = r["records"][1]
        self.assertEqual(
            gap["record_sha256"],
            raw_digest(data[gap["start"]:gap["end"]]))


class BoundaryAndResumeTests(MboxCase):
    def test_unfinished_last_record_waits_and_consumes_no_sequence_number(self):
        first = envelope("e1", eml_bytes("<m1@x>"))
        path = self.write_mbox("r.mbox",
                               [first, b"From e2\n", eml_bytes("<m2@x>")[:40]])
        r = mbox.mbox_scan(self.db, "R", path)
        self.assertEqual([x["record_number"] for x in r["records"]], [1])
        self.assertEqual(r["next_offset"], len(first))
        # appending the rest completes m2, and a following envelope makes it
        # processable; the final envelope-pinned record waits in turn
        path.write_bytes(path.read_bytes() + eml_bytes("<m2@x>")[40:]
                         + envelope("e3", eml_bytes("<m3@x>")) + b"From e4\n")
        r2 = mbox.mbox_scan(self.db, "R", path, limit=10)
        self.assertEqual([x["record_number"] for x in r2["records"]], [1, 2, 3])
        # sealing then lets the EOF-terminated last record (the e4 envelope) in
        r3 = mbox.mbox_scan(self.db, "R", path, seal=True)
        self.assertEqual([x["record_number"] for x in r3["records"]],
                         [1, 2, 3, 4])

    def test_pinned_prefix_includes_boundary_envelope_and_detects_rewrite(self):
        e1 = envelope("e1", eml_bytes("<m1@x>"))
        e2 = envelope("e2", eml_bytes("<m2@x>"))
        e3 = b"From e3\n"
        path = self.write_mbox("p.mbox", [e1, e2, e3])
        r = mbox.mbox_scan(self.db, "P", path)
        self.assertEqual(r["pinned_bytes"], len(e1 + e2 + e3))
        self.assertEqual(r["pinned_sha256"], raw_digest(e1 + e2 + e3))
        # rewrite the boundary envelope that proved record 2's end -> refused
        tampered = bytearray(path.read_bytes())
        tampered[len(e1 + e2)] = ord("x")  # first byte of the From e3 line
        path.write_bytes(bytes(tampered))
        os.utime(path, (1, 1))  # forged mtime cannot hide the byte change
        with self.assertRaisesRegex(ValueError, "committed mailbox prefix"):
            mbox.mbox_scan(self.db, "P", path)
        # shortening below the pinned length is refused too
        path.write_bytes(path.read_bytes()[:r["pinned_bytes"] - 1])
        with self.assertRaisesRegex(ValueError, "shorter than the committed"):
            mbox.mbox_scan(self.db, "P", path)

    def test_rewrite_after_pinned_boundary_is_allowed(self):
        e1 = envelope("e1", eml_bytes("<m1@x>"))
        e2 = envelope("e2", eml_bytes("<m2@x>"))
        e3 = b"From e3\n"
        path = self.write_mbox("p.mbox", [e1, e2, e3])
        mbox.mbox_scan(self.db, "P", path)
        rewritten = e1 + e2 + e3 + eml_bytes("<m3-rewritten@x>")
        path.write_bytes(rewritten)
        r = mbox.mbox_scan(self.db, "P", path, seal=True)
        self.assertEqual([x["status"] for x in r["records"]],
                         ["admitted", "admitted", "admitted"])
        self.assertEqual(r["source_sha256"], raw_digest(rewritten))

    def test_moving_the_file_keeps_source_identity(self):
        data = envelope("e1", eml_bytes("<m1@x>")) + envelope("e2")
        path = self.write_mbox("a.mbox", [data])
        r1 = mbox.mbox_scan(self.db, "M", path)
        moved = self.path("moved.mbox")
        path.rename(moved)
        r2 = mbox.mbox_scan(self.db, "M", moved)
        self.assertEqual(r1, r2)

    def test_seal_binds_whole_file_and_rejects_any_later_change(self):
        data = envelope("e1", eml_bytes("<m1@x>"))
        path = self.write_mbox("s.mbox", [data])
        r = mbox.mbox_scan(self.db, "S", path, seal=True)
        self.assertTrue(r["sealed"])
        self.assertEqual(r["pinned_bytes"], len(data))
        self.assertEqual(r["source_bytes"], len(data))
        self.assertEqual(r["source_sha256"], raw_digest(data))
        path.write_bytes(data + b"From appended\n")
        with self.assertRaisesRegex(ValueError, "sealed mailbox identity"):
            mbox.mbox_scan(self.db, "S", path)
        path.write_bytes(data)  # restore: repeated seal is a no-op, not re-seal
        self.assertEqual(mbox.mbox_scan(self.db, "S", path, seal=True), r)

    def test_seal_refuses_unfinished_envelope_but_accepts_ordinary_tail(self):
        path = self.path("u.mbox")
        path.write_bytes(envelope("e1", eml_bytes("<m1@x>")) + b"From dangling")
        with self.assertRaisesRegex(ValueError, "unfinished From line"):
            mbox.mbox_scan(self.db, "U", path, seal=True)
        path.write_bytes(envelope("e1", eml_bytes("<m1@x>", trailing_lf=False)))
        r = mbox.mbox_scan(self.db, "U", path, seal=True)
        self.assertTrue(r["sealed"])

    def test_empty_file_registers_seals_and_certifies(self):
        path = self.path("empty.mbox")
        path.write_bytes(b"")
        r = mbox.mbox_scan(self.db, "E", path, seal=True)
        self.assertEqual(r["records"], [])
        self.assertEqual(r["pinned_bytes"], 0)
        self.assertEqual(r["pinned_sha256"], hashlib.sha256(b"").hexdigest())
        cert = mbox.mbox_certify(self.db, "E")
        self.assertEqual(cert["records"], [])
        self.assertEqual(cert["source_bytes"], 0)
        self.assertEqual(cert["source_sha256"], hashlib.sha256(b"").hexdigest())

    def test_limit_truncation_and_default_upper_bound(self):
        chunks = [envelope(f"e{i}", eml_bytes(f"<m{i}@x>"))
                  for i in range(5)] + [b"From e5\n"]
        path = self.write_mbox("l.mbox", chunks)
        r = mbox.mbox_scan(self.db, "L", path, limit=2)
        self.assertEqual([x["record_number"] for x in r["records"]], [1, 2])
        r = mbox.mbox_scan(self.db, "L", path, limit=2)
        self.assertEqual([x["record_number"] for x in r["records"]], [1, 2, 3, 4])
        for bad in (0, 101, -1, True, 2.0):
            with self.assertRaises(ValueError):
                mbox.mbox_scan(self.db, "X", path, limit=bad)

    def test_first_line_rules(self):
        path = self.path("h.mbox")
        path.write_bytes(b"definitely not a mailbox\n")
        with self.assertRaisesRegex(ValueError, "From envelope"):
            mbox.mbox_scan(self.db, "H", path)
        path.write_bytes(b"Fro")  # still a possible From prefix: wait
        r = mbox.mbox_scan(self.db, "H", path)
        self.assertEqual(r["records"], [])
        # once the prefix can no longer become "From ", the whole command fails
        path.write_bytes(b"Front line without a separator\n")
        with self.assertRaisesRegex(ValueError, "From envelope"):
            mbox.mbox_scan(self.db, "H", path)
        # a short file whose bytes already diverge from the From prefix fails
        path.write_bytes(b"xy")
        with self.assertRaisesRegex(ValueError, "From envelope"):
            mbox.mbox_scan(self.db, "H2", path)

    def test_symlink_and_nonfile_sources_are_refused(self):
        real = self.write_mbox("real.mbox", [envelope("e", eml_bytes("<x@x>"))])
        link = self.path("link.mbox")
        link.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "symlink"):
            mbox.mbox_scan(self.db, "L", link)
        directory = self.path("folder")
        directory.mkdir()
        with self.assertRaises(ValueError):
            mbox.mbox_scan(self.db, "D", directory)


class AdmissionTests(MboxCase):
    def test_duplicate_bytes_ledger_each_record_but_ingest_once(self):
        message = eml_bytes("<dup@x>")
        path = self.write_mbox("d.mbox",
                               [envelope("d1", message), envelope("d2", message)])
        r = mbox.mbox_scan(self.db, "D", path, seal=True)
        self.assertEqual([x["admission"] for x in r["records"]],
                         ["inserted", "unchanged_live"])
        self.assertEqual(
            self.query("SELECT COUNT(*) FROM vault_messages WHERE id='<dup@x>'")[0][0], 1)
        self.assertEqual(
            [x["record_sha256"] for x in r["records"]],
            [raw_digest(envelope("d1", message)),
             raw_digest(envelope("d2", message))])

    def test_identity_conflict_and_reply_cycle_quarantine_without_residue(self):
        original = eml_bytes("<v@x>", body="original bytes")
        mbox.mbox_scan(self.db, "BASE",
                       self.write_mbox("b.mbox", [envelope("b", original)]),
                       seal=True)
        conflicting = eml_bytes("<v@x>", body="different bytes entirely")
        path = self.write_mbox("c.mbox", [
            envelope("c1", conflicting),
            envelope("c2", eml_bytes("<ok@x>"))])
        r = mbox.mbox_scan(self.db, "C", path, seal=True)
        self.assertEqual(
            [(x["status"], x.get("reason")) for x in r["records"]],
            [("unresolved", "identity_conflict"), ("admitted", None)])
        # two physical records jointly closing a cycle: c6 -> c7 -> c6
        path2 = self.write_mbox("y.mbox", [
            envelope("y1", eml_bytes("<c6@x>", parent="<c7@x>")),
            envelope("y2", eml_bytes("<c7@x>", parent="<c6@x>")),
            envelope("y3", eml_bytes("<post@x>"))])
        r2 = mbox.mbox_scan(self.db, "Y", path2, seal=True)
        self.assertEqual(r2["records"][0]["status"], "admitted")
        self.assertEqual(
            (r2["records"][1]["status"], r2["records"][1]["reason"]),
            ("unresolved", "reply_cycle"))
        self.assertEqual(r2["records"][2]["status"], "admitted")
        # the record that would close the cycle leaves no residue; the earlier
        # valid record stays admitted and the later one is unaffected
        for leaked in ("<c7@x>",):
            self.assertEqual(
                self.query("SELECT 1 FROM vault_messages WHERE id=?", (leaked,)), [])
            self.assertEqual(
                self.query("SELECT 1 FROM vault_search WHERE message_id=?",
                           (leaked,)), [])
            self.assertEqual(
                self.query("SELECT 1 FROM vault_attachments WHERE message_id=?",
                           (leaked,)), [])
        self.assertEqual(
            self.query("SELECT id FROM vault_messages WHERE id='<c6@x>'"),
            [("<c6@x>",)])
        # self-referential message is the shortest possible cycle
        path3 = self.write_mbox("z.mbox",
                                [envelope("z", eml_bytes("<self@x>",
                                                         parent="<self@x>"))])
        r3 = mbox.mbox_scan(self.db, "Z", path3, seal=True)
        self.assertEqual(r3["records"][0]["reason"], "reply_cycle")

    def test_quarantine_priority_oversize_before_invalid_mail(self):
        huge_invalid = b"From: h@x\nnot even headers" + b"Q" * (mbox.MAX_MESSAGE + 1)
        path = self.write_mbox("o.mbox",
                               [envelope("o", huge_invalid + b"\n"),
                                envelope("g", eml_bytes("<g@x>"))])
        r = mbox.mbox_scan(self.db, "O", path, seal=True)
        self.assertEqual(
            [(x["status"], x.get("reason")) for x in r["records"]],
            [("unresolved", "oversize"), ("admitted", None)])
        # an oversize record that is also unparseable is reported as oversize,
        # never truncated into a fake valid 2 MB message
        self.assertGreater(r["records"][0]["end"] - r["records"][0]["start"],
                           mbox.MAX_MESSAGE)

    def test_purged_redelivery_is_ignored_and_never_revived(self):
        message = eml_bytes("<pur@x>")
        mbox.mbox_scan(self.db, "PU",
                       self.write_mbox("pu.mbox", [envelope("p", message)]),
                       seal=True)
        vault.retention_plan(self.db, "PL", "2026-12-31T00:00:00Z")
        vault.retention_apply(self.db, "PL")
        self.assertEqual(vault.vault_search(self.db, "body"), [])
        path = self.write_mbox("pu2.mbox", [envelope("p2", message)])
        r = mbox.mbox_scan(self.db, "PU2", path, seal=True)
        self.assertEqual(r["records"][0]["admission"], "ignored_purged")
        self.assertEqual(vault.vault_search(self.db, "body"), [])


class ResolveTests(MboxCase):
    def _gap(self, source_id="Q", name="q.mbox"):
        path = self.write_mbox(name, [b"From broken\nnot a MIME message\n",
                                      envelope("g", eml_bytes("<g@x>"))])
        r = mbox.mbox_scan(self.db, source_id, path, seal=True)
        return path, r["records"][0]

    def test_waive_closes_gap_and_keeps_initial_reason(self):
        _, gap = self._gap()
        decision = self.path("w.json")
        decision.write_text(json.dumps({
            "source_id": "Q", "record_number": 1,
            "record_sha256": gap["record_sha256"],
            "action": "waive", "reason": "unrecoverable evidence"}))
        result = mbox.mbox_resolve(self.db, decision)
        self.assertEqual(result["status"], "waived")
        self.assertEqual(result["initial_reason"], "invalid_mail")
        self.assertEqual(result["reason"], "unrecoverable evidence")
        self.assertNotIn("message_id", result)
        # identical decision replay returns the same record object
        self.assertEqual(mbox.mbox_resolve(self.db, decision), result)
        cert = mbox.mbox_certify(self.db, "Q")
        self.assertEqual(cert["records"][0]["status"], "waived")
        self.assertNotIn("message_id", cert["records"][0])

    def test_replace_ingests_and_binds_both_digests(self):
        _, gap = self._gap("R", "r.mbox")
        fix = self.path("fix.eml")
        fix.write_bytes(eml_bytes("<fix@x>", parent=A))
        decision = self.path("d.json")
        decision.write_text(json.dumps({
            "source_id": "R", "record_number": 1,
            "record_sha256": gap["record_sha256"],
            "action": "replace", "reason": "operator supplied replacement",
            "replacement": "fix.eml"}))
        result = mbox.mbox_resolve(self.db, decision)
        self.assertEqual(result["status"], "replaced")
        self.assertEqual(result["admission"], "inserted")
        self.assertEqual(result["replacement_sha256"], raw_digest(fix.read_bytes()))
        self.assertEqual(result["message_sha256"], raw_digest(fix.read_bytes()))
        self.assertEqual(result["record_sha256"], gap["record_sha256"])
        # replay still reads and verifies the replacement file
        self.assertEqual(mbox.mbox_resolve(self.db, decision), result)
        fix.unlink()
        with self.assertRaises(ValueError):
            mbox.mbox_resolve(self.db, decision)

    def test_replacement_conflict_keeps_gap_unresolved(self):
        original = eml_bytes("<v@x>", body="original")
        mbox.mbox_scan(self.db, "BASE",
                       self.write_mbox("b.mbox", [envelope("b", original)]),
                       seal=True)
        _, gap = self._gap("Q", "q.mbox")
        fix = self.path("fix.eml")
        fix.write_bytes(eml_bytes("<v@x>", body="conflicting different bytes"))
        decision = self.path("d.json")
        decision.write_text(json.dumps({
            "source_id": "Q", "record_number": 1,
            "record_sha256": gap["record_sha256"],
            "action": "replace", "reason": "try conflict",
            "replacement": "fix.eml"}))
        with self.assertRaisesRegex(ValueError, "identity graph"):
            mbox.mbox_resolve(self.db, decision)
        show = mbox.mbox_show(self.db, "Q")
        self.assertEqual(show["records"][0]["status"], "unresolved")
        self.assertEqual(
            self.query("SELECT COUNT(*) FROM vault_messages WHERE id='<v@x>'")[0][0], 1)

    def test_decision_validation_and_cross_source_isolation(self):
        _, gap = self._gap("Q", "q.mbox")
        other_path = self.write_mbox("q2.mbox", [b"From b\njunk\n"])
        other = mbox.mbox_scan(self.db, "Q2", other_path, seal=True)
        decision = self.path("d.json")
        # digest from Q2 must not resolve Q's record 1
        decision.write_text(json.dumps({
            "source_id": "Q", "record_number": 1,
            "record_sha256": other["records"][0]["record_sha256"],
            "action": "waive", "reason": "x"}))
        with self.assertRaisesRegex(ValueError, "record_sha256 does not match"):
            mbox.mbox_resolve(self.db, decision)
        # strict structure: duplicate keys, non-finite numbers and 8 MB guard
        decision.write_text(
            '{"source_id":"Q","record_number":1,"record_number":2,'
            '"record_sha256":"%s","action":"waive","reason":"x"}'
            % gap["record_sha256"])
        with self.assertRaises(ValueError):
            mbox.mbox_resolve(self.db, decision)
        for payload in (
                {"source_id": "Q", "record_number": 1,
                 "record_sha256": gap["record_sha256"],
                 "action": "waive", "reason": "   "},
                {"source_id": "Q", "record_number": True,
                 "record_sha256": gap["record_sha256"],
                 "action": "waive", "reason": "x"},
                {"source_id": "Q", "record_number": 1,
                 "record_sha256": "ABCDEF", "action": "waive", "reason": "x"},
                {"source_id": "Q", "record_number": 1,
                 "record_sha256": gap["record_sha256"],
                 "action": "explode", "reason": "x"},
                {"source_id": "Q", "record_number": 1,
                 "record_sha256": gap["record_sha256"],
                 "action": "replace", "reason": "x",
                 "replacement": "missing.eml"}):
            decision.write_text(json.dumps(payload))
            with self.assertRaises(ValueError):
                mbox.mbox_resolve(self.db, decision)
        # admitted records cannot be re-decided
        good_decision = self.path("ok.json")
        good_decision.write_text(json.dumps({
            "source_id": "Q", "record_number": 2,
            "record_sha256": mbox.mbox_show(self.db, "Q")["records"][1]["record_sha256"],
            "action": "waive", "reason": "nope"}))
        with self.assertRaisesRegex(ValueError, "admitted records cannot"):
            mbox.mbox_resolve(self.db, good_decision)

    def test_resolved_record_cannot_change_decision(self):
        _, gap = self._gap()
        first = self.path("w.json")
        first.write_text(json.dumps({
            "source_id": "Q", "record_number": 1,
            "record_sha256": gap["record_sha256"],
            "action": "waive", "reason": "first decision"}))
        mbox.mbox_resolve(self.db, first)
        second = self.path("w2.json")
        second.write_text(json.dumps({
            "source_id": "Q", "record_number": 1,
            "record_sha256": gap["record_sha256"],
            "action": "waive", "reason": "different decision"}))
        with self.assertRaisesRegex(ValueError, "different final disposition"):
            mbox.mbox_resolve(self.db, second)


class CertifyTests(MboxCase):
    def test_certify_gates_and_frozen_document(self):
        # unsealed source cannot certify
        path = self.write_mbox("u.mbox",
                               [envelope("e", eml_bytes("<u@x>")), b"From n\n"])
        mbox.mbox_scan(self.db, "U", path)
        with self.assertRaisesRegex(ValueError, "unsealed"):
            mbox.mbox_certify(self.db, "U")
        # a sealed source whose records have not all been scanned yet: the
        # last complete envelope starts another record that cannot finish
        # before EOF, so it is scanned only across later commands
        waiting = self.write_mbox("w.mbox",
                                  [envelope("w", eml_bytes("<w@x>")),
                                   envelope("pending", eml_bytes("<pending@x>"))])
        mbox.mbox_scan(self.db, "W", waiting, seal=True, limit=1)
        with self.assertRaisesRegex(ValueError, "every physical record"):
            mbox.mbox_certify(self.db, "W")
        # a sealed source with a quarantined gap also refuses
        gap = self.write_mbox("g.mbox", [b"From b\njunk\n"])
        mbox.mbox_scan(self.db, "G", gap, seal=True)
        with self.assertRaisesRegex(ValueError, "quarantined"):
            mbox.mbox_certify(self.db, "G")
        # complete, fully resolved source certifies and then freezes
        complete = self.write_mbox("c.mbox", [envelope("c", eml_bytes("<c@x>"))])
        mbox.mbox_scan(self.db, "C", complete, seal=True)
        cert = mbox.mbox_certify(self.db, "C")
        self.assertEqual(list(cert), ["vault", "source_id", "source_bytes",
                                      "source_sha256", "records"])
        self.assertEqual(mbox.mbox_certify(self.db, "C"), cert)
        with self.assertRaisesRegex(ValueError, "unknown mbox"):
            mbox.mbox_certify(self.db, "GHOST")

    def test_certificate_survives_later_purge_with_first_classification(self):
        message = eml_bytes("<m@x>")
        path = self.write_mbox("m.mbox", [envelope("e", message)])
        mbox.mbox_scan(self.db, "M", path, seal=True)
        cert = mbox.mbox_certify(self.db, "M")
        vault.retention_plan(self.db, "PL", "2026-12-31T00:00:00Z")
        vault.retention_apply(self.db, "PL")
        self.assertEqual(vault.vault_search(self.db, "body"), [])
        self.assertEqual(mbox.mbox_certify(self.db, "M"), cert)
        self.assertEqual(mbox.mbox_show(self.db, "M")["certificate"], cert)
        # ledger identity remains even though payload is gone
        self.assertEqual(
            mbox.mbox_show(self.db, "M")["records"][0]["message_id"], "<m@x>")


class TimelineTests(MboxCase):
    def test_late_parent_reroots_reply_and_hold_blocks_old_plan(self):
        # Baseline R replies to a missing P; an anchor-A hold does not cover R.
        seed = self.root / "seed2"
        seed.mkdir()
        write_eml(seed, "r.eml", R, parent=P, body="r body")
        db2 = self.root / "timeline.sqlite"
        vault.init(seed, db2)
        recovery.enable(db2)
        vault.hold_add(db2, "HOLD-A", A)
        vault.retention_plan(db2, "PLAN", "2026-12-31T00:00:00Z")
        # Mbox: P's physical record is invalid, S is admitted, X waits.
        mbox_path = self.root / "mbx.mbox"
        mbox_path.write_bytes(
            b"From env-p\nbroken P MIME bytes\n"
            + envelope("env-s", eml_bytes("<S@x>"))
            + b"From env-x\n" + eml_bytes("<X@x>")[:30])
        first = mbox.mbox_scan(db2, "MBX", mbox_path)
        self.assertEqual(
            [(x["status"], x.get("reason")) for x in first["records"]],
            [("unresolved", "invalid_mail"), ("admitted", None)])
        # Completing append processes X exactly once.
        mbox_path.write_bytes(
            mbox_path.read_bytes() + eml_bytes("<X@x>")[30:]
            + envelope("env-x2", eml_bytes("<X2@x>")))
        second = mbox.mbox_scan(db2, "MBX", mbox_path)
        self.assertEqual([x["record_number"] for x in second["records"]], [1, 2, 3])
        # Replace P with a valid mail that replies to anchor A.
        fix = self.root / "p-fix.eml"
        fix.write_bytes(eml_bytes(P, parent=A))
        decision = self.root / "decision.json"
        decision.write_text(json.dumps({
            "source_id": "MBX", "record_number": 1,
            "record_sha256": first["records"][0]["record_sha256"],
            "action": "replace",
            "reason": "P recovered and now chains to anchor A",
            "replacement": "p-fix.eml"}))
        resolved = mbox.mbox_resolve(db2, decision)
        self.assertEqual(resolved["status"], "replaced")
        # R re-roots to A through the completed parent graph.
        rnode = [n for n in vault.vault_thread(db2, R) if n["id"] == R][0]
        self.assertEqual(rnode["thread_id"], A)
        # The pre-existing purge plan is now blocked by current hold coverage.
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(db2, "PLAN")
        self.assertIn(R, [item["id"] for item in ctx.exception.blocked])
        # Sealing and certifying bind the original bad bytes and replacement.
        mbox.mbox_scan(db2, "MBX", mbox_path, seal=True)
        cert = mbox.mbox_certify(db2, "MBX")
        record = cert["records"][0]
        self.assertEqual(record["record_sha256"],
                         first["records"][0]["record_sha256"])
        self.assertEqual(record["replacement_sha256"],
                         resolved["replacement_sha256"])
        self.assertEqual(record["status"], "replaced")


class RevisionTests(MboxCase):
    def test_each_business_command_advances_once_and_noops_do_not(self):
        recovery.enable(self.db)
        self.assertEqual(recovery.info(self.db)["revision"], 0)
        # the dangling e3 envelope keeps the last record open until sealed
        path = self.write_mbox("m.mbox", [
            envelope("e1", eml_bytes("<m1@x>")),
            envelope("e2", eml_bytes("<m2@x>")),
            b"From e3\n", eml_bytes("<m3@x>")])
        mbox.mbox_scan(self.db, "M", path, limit=1)  # one record in one command
        self.assertEqual(recovery.info(self.db)["revision"], 1)
        mbox.mbox_scan(self.db, "M", path, limit=1)  # second record
        self.assertEqual(recovery.info(self.db)["revision"], 2)
        mbox.mbox_scan(self.db, "M", path)  # nothing new: successful no-op
        self.assertEqual(recovery.info(self.db)["revision"], 2)
        mbox.mbox_show(self.db, "M")  # read-only
        self.assertEqual(recovery.info(self.db)["revision"], 2)
        # sealing lets the EOF-terminated third record in, a business change
        mbox.mbox_scan(self.db, "M", path, seal=True)
        self.assertEqual(recovery.info(self.db)["revision"], 3)
        mbox.mbox_scan(self.db, "M", path, seal=True)  # repeat seal no-op
        self.assertEqual(recovery.info(self.db)["revision"], 3)
        cert = mbox.mbox_certify(self.db, "M")  # first certificate advances
        self.assertEqual(recovery.info(self.db)["revision"], 4)
        mbox.mbox_certify(self.db, "M")  # frozen replay
        self.assertEqual(recovery.info(self.db)["revision"], 4)
        # an empty source registration is business, including its first seal
        empty = self.path("e.mbox")
        empty.write_bytes(b"")
        mbox.mbox_scan(self.db, "E", empty, seal=True)
        self.assertEqual(recovery.info(self.db)["revision"], 5)

    def test_failed_scan_leaves_revision_and_ledger_untouched(self):
        recovery.enable(self.db)
        path = self.write_mbox("m.mbox", [
            envelope("e1", eml_bytes("<m1@x>")), envelope("e2", eml_bytes("<m2@x>"))])
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and "INSERT INTO vault_mbox_records" in sql:
                    raise sqlite3.OperationalError("injected crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect", side_effect=lambda *a, **k: real_connect(
                *a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                mbox.mbox_scan(self.db, "M", path)
        self.assertEqual(recovery.info(self.db)["revision"], 0)
        self.assertEqual(self.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vault_mbox%'"), [])
        # clean retry processes everything with no gap or duplicate numbering
        r = mbox.mbox_scan(self.db, "M", path, seal=True)
        self.assertEqual([x["record_number"] for x in r["records"]], [1, 2])
        self.assertEqual(recovery.info(self.db)["revision"], 1)


class RecoveryIntegrationTests(MboxCase):
    def _build_ledger_vault(self):
        recovery.enable(self.db)
        gap_path = self.write_mbox("g.mbox",
                                   [b"From b\nbroken mime\n",
                                    envelope("ok", eml_bytes("<ok@x>"))])
        scanned = mbox.mbox_scan(self.db, "S1", gap_path, seal=True)
        fix = self.path("fix.eml")
        fix.write_bytes(eml_bytes("<fix@x>"))
        decision = self.path("d.json")
        decision.write_text(json.dumps({
            "source_id": "S1", "record_number": 1,
            "record_sha256": scanned["records"][0]["record_sha256"],
            "action": "replace", "reason": "replaced before checkpoint",
            "replacement": "fix.eml"}))
        mbox.mbox_resolve(self.db, decision)
        waived_path = self.write_mbox("w.mbox", [b"From b2\njunk\n"])
        waived = mbox.mbox_scan(self.db, "S2", waived_path, seal=True)
        wd = self.path("wd.json")
        wd.write_text(json.dumps({
            "source_id": "S2", "record_number": 1,
            "record_sha256": waived["records"][0]["record_sha256"],
            "action": "waive", "reason": "waived before checkpoint"}))
        mbox.mbox_resolve(self.db, wd)
        cert = mbox.mbox_certify(self.db, "S2")
        return scanned, cert

    def test_checkpoint_restore_preserves_ledger_and_freezes_certificate(self):
        scanned, cert = self._build_ledger_vault()
        checkpoint = self.path("cp.json")
        cp_result = recovery.checkpoint(self.db, checkpoint)
        authority = self.path("au.json")
        recovery.authority(self.db, authority)
        recovered = self.path("recovered.sqlite")
        recovery.restore(
            checkpoint, raw_digest(checkpoint.read_bytes()),
            authority, raw_digest(authority.read_bytes()),
            cp_result["revision"], recovered)
        show1 = mbox.mbox_show(recovered, "S1")
        self.assertEqual(show1["records"][0]["status"], "replaced")
        self.assertEqual(show1["records"][0]["initial_reason"], "invalid_mail")
        show2 = mbox.mbox_show(recovered, "S2")
        self.assertEqual(show2["records"][0]["status"], "waived")
        self.assertEqual(show2["certificate"], cert)
        # every mutation entry is refused on the recovered copy, even a true
        # replay, and the refusal happens before external files are read
        decision = self.path("d.json")
        for call in (lambda: mbox.mbox_scan(recovered, "S1", self.path("g.mbox")),
                     lambda: mbox.mbox_certify(recovered, "S1"),
                     lambda: mbox.mbox_resolve(recovered, decision),
                     lambda: mbox.mbox_resolve(recovered, self.path("missing.json"))):
            with self.assertRaises(vault.RecoveredVault):
                call()
        with self.assertRaisesRegex(ValueError, "unknown mbox"):
            mbox.mbox_show(recovered, "NEVER-EXISTED")

    def test_old_checkpoint_without_mbox_tables_still_restores(self):
        recovery.enable(self.db)
        checkpoint = self.path("cp.json")
        recovery.checkpoint(self.db, checkpoint)
        document = json.loads(checkpoint.read_bytes())
        for name in [name for name in document["tables"]
                     if name.startswith("vault_mbox")]:
            del document["tables"][name]
        base = {key: value for key, value in document.items()
                if key != "checksum"}
        document["checksum"] = hashlib.sha256(
            json.dumps(base, **CANONICAL).encode()).hexdigest()
        old = self.path("old.json")
        old.write_bytes(json.dumps(document, **CANONICAL).encode())
        authority = self.path("au.json")
        recovery.authority(self.db, authority)
        recovered = self.path("old-recovered.sqlite")
        recovery.restore(old, raw_digest(old.read_bytes()), authority,
                         raw_digest(authority.read_bytes()), 0, recovered)
        with self.assertRaisesRegex(ValueError, "unknown mbox"):
            mbox.mbox_show(recovered, "ANY")
        with self.assertRaises(vault.RecoveredVault):
            mbox.mbox_scan(recovered, "NEW", self.path("g.mbox"))

    def test_restore_older_checkpoint_keeps_history_and_blocks_new_writes(self):
        scanned, _ = self._build_ledger_vault()
        checkpoint = self.path("cp.json")
        cp_result = recovery.checkpoint(self.db, checkpoint)
        authority = self.path("au.json")
        recovery.authority(self.db, authority)
        recovered = self.path("recovered.sqlite")
        recovery.restore(
            checkpoint, raw_digest(checkpoint.read_bytes()), authority,
            raw_digest(authority.read_bytes()), cp_result["revision"], recovered)
        # Later evolution of the source vault must not inject into the exhibit.
        later = self.write_mbox("later.mbox", [envelope("l", eml_bytes("<l@x>"))])
        mbox.mbox_scan(self.db, "LATER", later, seal=True)
        with self.assertRaisesRegex(ValueError, "unknown mbox"):
            mbox.mbox_show(recovered, "LATER")
        # The historical unresolved/replaced ledger is still exactly as captured.
        self.assertEqual(
            [x["status"] for x in mbox.mbox_show(recovered, "S1")["records"]],
            ["replaced", "admitted"])
        # mbox-show is read-only: running it changes nothing on the copy.
        before = recovered.read_bytes()
        mbox.mbox_show(recovered, "S1")
        self.assertEqual(recovered.read_bytes(), before)

    def test_newer_authority_purge_keeps_ledger_and_frozen_certificate(self):
        # Checkpoint holds an unresolved gap and a resolved (waived) gap plus a
        # fully admitted source with a certificate.  After the checkpoint the
        # admitted mail is purged and a newer authority suppresses it; restore
        # must keep the ledger and certificate untouched with no payload return.
        recovery.enable(self.db)
        sealed = self.write_mbox(
            "cert.mbox", [envelope("c", eml_bytes("<certmail@x>"))])
        mbox.mbox_scan(self.db, "CERT", sealed, seal=True)
        certificate = mbox.mbox_certify(self.db, "CERT")
        gap_path = self.write_mbox("gap.mbox", [b"From b\nbroken\n"])
        gap_scan = mbox.mbox_scan(self.db, "GAP", gap_path, seal=True)
        waived_decision = self.path("waive.json")
        waived_decision.write_text(json.dumps({
            "source_id": "GAP", "record_number": 1,
            "record_sha256": gap_scan["records"][0]["record_sha256"],
            "action": "waive", "reason": "waived at checkpoint time"}))
        mbox.mbox_resolve(self.db, waived_decision)
        open_gap_path = self.write_mbox("open.mbox", [b"From o\nstill broken\n"])
        open_scan = mbox.mbox_scan(self.db, "OPEN", open_gap_path, seal=True)
        self.assertEqual(open_scan["records"][0]["status"], "unresolved")
        checkpoint = self.path("cp.json")
        cp_result = recovery.checkpoint(self.db, checkpoint)
        # Post-checkpoint: resolve the open gap, purge the certified mail, then
        # export an authority that is newer than the checkpoint.
        later_decision = self.path("later.json")
        later_decision.write_text(json.dumps({
            "source_id": "OPEN", "record_number": 1,
            "record_sha256": open_scan["records"][0]["record_sha256"],
            "action": "waive", "reason": "resolved after checkpoint"}))
        mbox.mbox_resolve(self.db, later_decision)
        vault.retention_plan(self.db, "PURGE", "2026-12-31T00:00:00Z")
        vault.retention_apply(self.db, "PURGE")
        authority = self.path("au.json")
        au_result = recovery.authority(self.db, authority)
        recovered = self.path("recovered.sqlite")
        recovery.restore(
            checkpoint, raw_digest(checkpoint.read_bytes()), authority,
            raw_digest(authority.read_bytes()), cp_result["revision"], recovered)
        # The checkpoint-era open gap is still unresolved in the exhibit; the
        # later resolution never injects.
        self.assertEqual(
            mbox.mbox_show(recovered, "OPEN")["records"][0]["status"],
            "unresolved")
        # The waived gap and replaced/waived history survive as captured.
        self.assertEqual(
            mbox.mbox_show(recovered, "GAP")["records"][0]["status"], "waived")
        # The certified mail is suppressed, but its certificate and first
        # classification remain frozen and payload does not come back.
        self.assertEqual(
            mbox.mbox_show(recovered, "CERT")["certificate"], certificate)
        self.assertEqual(vault.vault_search(recovered, "body"), [])
        cert_record = mbox.mbox_show(recovered, "CERT")["records"][0]
        self.assertEqual(cert_record["admission"], "inserted")
        # Every write entry, including a true replay, is refused on the copy.
        with self.assertRaises(vault.RecoveredVault):
            mbox.mbox_resolve(recovered, later_decision)
        with self.assertRaises(vault.RecoveredVault):
            mbox.mbox_scan(recovered, "CERT", sealed)
        with self.assertRaises(vault.RecoveredVault):
            mbox.mbox_certify(recovered, "CERT")
        self.assertGreaterEqual(au_result["revision"], cp_result["revision"])


class GuardTests(MboxCase):
    def test_v1_and_missing_databases_are_never_created_or_modified(self):
        v1_path = self.path("v1.sqlite")
        v1_build(self.root / "seed", v1_path)
        before = v1_path.read_bytes()
        source = self.write_mbox("s.mbox", [envelope("e", eml_bytes("<x@x>"))])
        with self.assertRaises(ValueError):
            mbox.mbox_scan(v1_path, "X", source)
        with self.assertRaises(ValueError):
            mbox.mbox_show(v1_path, "X")
        self.assertEqual(v1_path.read_bytes(), before)
        missing = self.path("missing.sqlite")
        with self.assertRaises((ValueError, sqlite3.Error)):
            mbox.mbox_scan(missing, "X", source)
        with self.assertRaises((ValueError, sqlite3.Error)):
            mbox.mbox_certify(missing, "X")
        self.assertFalse(missing.exists())

    def test_cli_exit_codes_and_show_shape(self):
        source = self.write_mbox("s.mbox", [envelope("e", eml_bytes("<x@x>"))])
        code, out, err = self.run_cli(
            "mbox-scan", "--db", str(self.db), "--source-id", "S",
            "--source", str(source), "--seal")
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        payload = json.loads(out)
        self.assertEqual(list(payload), [
            "vault", "source_id", "next_offset", "pinned_bytes", "pinned_sha256",
            "sealed", "source_bytes", "source_sha256", "records", "certificate"])
        code, _, _ = self.run_cli(
            "mbox-show", "--db", str(self.db), "--source-id", "GHOST")
        self.assertEqual(code, 2)
        code, out, _ = self.run_cli(
            "mbox-certify", "--db", str(self.db), "--source-id", "S")
        self.assertEqual(code, 0)
        cert = json.loads(out)
        self.assertEqual(list(cert), ["vault", "source_id", "source_bytes",
                                      "source_sha256", "records"])


if __name__ == "__main__":
    unittest.main()
