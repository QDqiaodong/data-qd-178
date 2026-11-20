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

from mailroom import cli, review, vault
from mailroom.archive import build as v1_build
from mailroom.parse import read_folder

MARKER = "[REDACTED]"
CANONICAL_KW = dict(ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False)


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


def digest_of(value):
    return hashlib.sha256(json.dumps(value, **CANONICAL_KW).encode("utf-8")).hexdigest()


def canonical_bytes(value):
    return json.dumps(value, **CANONICAL_KW).encode("utf-8")


class ReviewCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"

    def batch(self, name):
        folder = self.root / name
        folder.mkdir()
        return folder

    def write_json(self, name, value):
        path = self.root / name
        path.write_bytes(canonical_bytes(value) if not isinstance(value, bytes) else value)
        return path

    def query(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def init_messages(self, bodies):
        """bodies: {message_id: (body, parent_or_None)}; returns parsed bodies."""
        folder = self.batch("mail")
        for number, (msg_id, (body, parent)) in enumerate(sorted(bodies.items())):
            write_eml(folder, f"{number:03}.eml", msg_id, parent=parent, body=body)
        vault.init(folder, self.db)
        return {msg_id: read_folder(folder)[msg_id]["body"] for msg_id in bodies}

    def open_review(self, review_id, selections, spec_name="spec.json"):
        spec = {"review_id": review_id,
                "messages": [{"message_id": mid, "redactions": reds}
                             for mid, reds in selections]}
        path = self.write_json(spec_name, spec)
        return review.review_open(self.db, path), path

    def export(self, review_id="R1", name="package.json"):
        path = self.root / name
        result = review.review_export(self.db, review_id, path)
        return path, json.loads(path.read_bytes()), result


class RedactionLogicTests(ReviewCase):
    def test_union_of_overlapping_adjacent_and_shuffled_intervals(self):
        body = "abcdefXYZghi"
        for ordering in ([[2, 4], [3, 6]], [[3, 6], [2, 4]], [[2, 5], [5, 6]]):
            merged = review._merge_ranges((s, e) for s, e in ordering)
            self.assertEqual(merged, [[2, 6]])
            text, runs = review._redact(body, merged)
            self.assertEqual(text, "ab[REDACTED]XYZghi")
        # equivalent split of the same union merges identically
        self.assertEqual(review._merge_ranges([(2, 3), (3, 4), (4, 6)]), [[2, 6]])

    def test_spec_example_coordinate_back_mapping(self):
        body = "abcdefXYZghi"
        text, runs = review._redact(body, [[2, 6]])
        self.assertEqual(text, "ab[REDACTED]XYZghi")
        # delivered [12,15) is XYZ; source must be [6,9), not [12,15)
        self.assertEqual(review._map_span(runs, len(text), 12, 15, "x"), (6, 9))

    def test_multiple_different_length_shifts_compound(self):
        body = "0123456789ABCDEF"
        intervals = [[1, 3], [6, 10]]  # two redactions, each replaced by 10 chars
        text, runs = review._redact(body, intervals)
        self.assertEqual(text, "0" + MARKER + "345" + MARKER + "ABCDEF")
        # delivered position of "ABCDEF": 1 + 10 + 3 + 10 = 24
        self.assertEqual(text[24:30], "ABCDEF")
        self.assertEqual(review._map_span(runs, len(text), 24, 30, "x"), (10, 16))
        self.assertEqual(review._map_span(runs, len(text), 25, 27, "x"), (11, 13))

    def test_literal_marker_is_annotatable_but_inserted_marker_is_not(self):
        body = "xx[REDACTED]yy"  # literal marker spans source 2..12
        intervals = [[0, 2]]      # inserted marker replaces xx
        text, runs = review._redact(body, intervals)
        self.assertEqual(text, MARKER + "[REDACTED]yy")
        literal_start = len(MARKER)
        # the literal marker survived and is a normal retained run
        self.assertEqual(review._map_span(runs, len(text),
                                          literal_start, literal_start + 10, "x"), (2, 12))
        # any span touching the inserted marker is rejected, without string search
        for start, end in ((0, 1), (5, 13), (9, 11)):
            with self.assertRaisesRegex(ValueError, r"touches inserted"):
                review._map_span(runs, len(text), start, end, "x")

    def test_unicode_code_points_not_utf16_or_utf8_units(self):
        body = "aé日本語z"  # 6 code points
        text, runs = review._redact(body, [[1, 2]])  # redact é
        self.assertEqual(text, "a" + MARKER + "日本語z")
        jp = text.index("日")
        self.assertEqual(review._map_span(runs, len(text), jp, jp + 3, "x"), (2, 5))
        self.assertEqual(len(text), 1 + len(MARKER) + 4)

    def test_boolean_and_float_endpoints_rejected(self):
        with self.assertRaisesRegex(ValueError, "integer"):
            review._merge_intervals([[True, 3]], 10, "redactions")
        with self.assertRaisesRegex(ValueError, "integer"):
            review._merge_intervals([[1, 2.0]], 10, "redactions")


class OpenTests(ReviewCase):
    def test_registration_summary_and_persisted_coordinates_only(self):
        bodies = self.init_messages({"<m1@x>": ("secret body alpha", None),
                                    "<m2@x>": ("another secret body", "<m1@x>")})
        (summary, _) = self.open_review("R1", [("<m2@x>", [[8, 14]]), ("<m1@x>", [])])
        self.assertEqual(summary, {"review_id": "R1", "item_count": 2})
        rows = self.query("SELECT message_id,item_id,parent_item_id,intervals "
                          "FROM vault_review_items ORDER BY ord")
        self.assertEqual([r[0] for r in rows], ["<m1@x>", "<m2@x>"])  # sorted by source ID
        self.assertEqual([r[1] for r in rows], ["M0001", "M0002"])
        self.assertEqual([r[2] for r in rows], [None, "M0001"])
        self.assertEqual(json.loads(rows[1][3]), [[8, 14]])
        # no payload of any kind is copied into review tables
        stored = "\n".join(str(r) for r in
                           self.query("SELECT intervals FROM vault_review_items"))
        self.assertNotIn("secret", stored)
        self.assertEqual(self.query(
            "SELECT count(*) FROM vault_review_items WHERE intervals LIKE '%body%'"), [(0,)])

    def test_equivalent_spec_retries_ignore_order_and_interval_splits(self):
        self.init_messages({"<m1@x>": ("abcdefXYZghijklmnop", None),
                            "<m2@x>": ("qrstuvwxyz", None)})
        spec = {"review_id": "R1", "messages": [
            {"message_id": "<m2@x>", "redactions": [[2, 5]]},
            {"message_id": "<m1@x>", "redactions": [[3, 6], [2, 4]]}]}  # unordered, overlap
        first_path = self.write_json("s1.json", spec)
        first = review.review_open(self.db, first_path)
        equivalent = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[2, 3], [3, 4], [4, 6]]},  # split union
            {"message_id": "<m2@x>", "redactions": [[2, 3], [3, 5]]}]}  # adjacent split
        second_path = self.write_json("s2.json", equivalent)
        self.assertEqual(review.review_open(self.db, second_path), first)
        changed = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[2, 7]]},  # union actually changes
            {"message_id": "<m2@x>", "redactions": [[2, 5]]}]}
        with self.assertRaisesRegex(ValueError, "different specification"):
            review.review_open(self.db, self.write_json("s3.json", changed))
        different_set = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[2, 6]]}]}
        with self.assertRaisesRegex(ValueError, "different specification"):
            review.review_open(self.db, self.write_json("s4.json", different_set))

    def test_retry_succeeds_after_source_purge_without_live_check(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        self.open_review("R1", [("<m1@x>", [[1, 3]])])
        vault.retention_plan(self.db, "P", "2026-11-30T00:00:00Z")
        vault.retention_apply(self.db, "P")
        again = review.review_open(self.db, self.write_json(
            "spec2.json", {"review_id": "R1",
                           "messages": [{"message_id": "<m1@x>", "redactions": [[1, 3]]}]}))
        self.assertEqual(again, {"review_id": "R1", "item_count": 1})

    def test_spec_validation_rules(self):
        folder = self.batch("mail")
        write_eml(folder, "m1.eml", "<m1@x>", body="ab")   # body "ab\n" -> 3 code points
        write_eml(folder, "m2.eml", "<m2@x>", body="gh")   # body "gh\n" -> 3 code points
        vault.init(folder, self.db)
        base = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[0, 1]]}]}

        def must_fail(value, pattern):
            with self.assertRaisesRegex(ValueError, pattern):
                review.review_open(self.db, self.write_json("bad.json", value))

        bad_id = json.loads(json.dumps(base))
        bad_id["review_id"] = ".bad"
        must_fail(bad_id, "must match")
        extra = json.loads(json.dumps(base))
        extra["unexpected"] = True
        must_fail(extra, "exactly these keys")
        dup = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": []},
            {"message_id": "<m1@x>", "redactions": []}]}
        must_fail(dup, "must not repeat")
        must_fail({"review_id": "R1", "messages": []}, "1..200")
        unknown = {"review_id": "R1", "messages": [
            {"message_id": "<ghost@x>", "redactions": []}]}
        must_fail(unknown, "not a current live message")
        out_of_range = {"review_id": "R1", "messages": [
            {"message_id": "<m2@x>", "redactions": [[0, 4]]}]}  # body length is 3
        must_fail(out_of_range, "body length")
        zero_width = {"review_id": "R1", "messages": [
            {"message_id": "<m2@x>", "redactions": [[1, 1]]}]}
        must_fail(zero_width, "start < end")
        wrong_shape = {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[1]]}]}
        must_fail(wrong_shape, r"\[start,end\]")

    def test_purged_message_cannot_be_newly_selected(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        vault.retention_plan(self.db, "P", "2026-11-30T00:00:00Z")
        vault.retention_apply(self.db, "P")
        with self.assertRaisesRegex(ValueError, "not a current live message"):
            self.open_review("R9", [("<m1@x>", [])])

    def test_empty_body_only_allows_empty_interval_list(self):
        folder = self.batch("mail")
        write_eml(folder, "m.eml", "<empty@x>", body="")
        vault.init(folder, self.db)
        body = read_folder(folder)["<empty@x>"]["body"]
        self.assertEqual(body, "\n")  # parser always appends the separating newline
        spec = {"review_id": "R1", "messages": [
            {"message_id": "<empty@x>", "redactions": []}]}
        summary = review.review_open(self.db, self.write_json("spec.json", spec))
        self.assertEqual(summary["item_count"], 1)

    def test_duplicate_json_key_and_non_finite_numbers_rejected(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        raw = b'{"review_id":"R1","review_id":"R2","messages":[]}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            review.review_open(self.db, self.write_json("dup.json", raw))
        raw = b'{"review_id":"R1","messages":[{"message_id":"<m1@x>","redactions":[[0,NaN]]}]}'
        with self.assertRaisesRegex(ValueError, "non-finite"):
            review.review_open(self.db, self.write_json("nan.json", raw))

    def test_package_size_limit_checked_before_registration(self):
        folder = self.batch("mail")
        # every message stays under the 2 MB MIME limit; the redacted package
        # itself is what must be refused beyond 8 MB (5 * ~1.9 MB > 8 MB)
        for number in range(5):
            write_eml(folder, f"m{number}.eml", f"<m{number}@x>", body="x" * 1_900_000)
        vault.init(folder, self.db)
        spec = {"review_id": "BIG", "messages": [
            {"message_id": f"<m{number}@x>", "redactions": []} for number in range(5)]}
        with self.assertRaisesRegex(ValueError, "8,000,000 bytes"):
            review.review_open(self.db, self.write_json("spec.json", spec))
        # the oversized batch is refused before any review table is created
        self.assertEqual(self.query(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'vault_review%'"), [(0,)])


class ExportTests(ReviewCase):
    def test_package_structure_digest_and_compact_encoding_golden_values(self):
        self.init_messages({"<m1@x>": ("abcdefXYZghi", None)})
        self.open_review("R1", [("<m1@x>", [[2, 6]])])
        path, package, result = self.export()
        self.assertEqual(set(package), {"format", "review_id", "items", "package_sha256"})
        self.assertEqual(package["format"], "mailroom-review-1")
        self.assertEqual(package["review_id"], "R1")
        self.assertEqual(package["items"], [
            {"item_id": "M0001", "parent_item_id": None,
             "text": "ab[REDACTED]XYZghi\n"}])
        # independently recompute the expected digest from the spec's encoding rule
        base = {"format": "mailroom-review-1", "review_id": "R1",
                "items": package["items"]}
        expected = digest_of(base)
        self.assertEqual(package["package_sha256"], expected)
        self.assertEqual(result["package_sha256"], expected)
        raw = path.read_bytes()
        self.assertEqual(raw, canonical_bytes(package))  # sorted keys, compact, no newline
        self.assertFalse(raw.endswith(b"\n"))

    def test_parent_item_id_only_for_selected_direct_parent(self):
        self.init_messages({
            "<g@x>": ("grandparent", None),
            "<p@x>": ("parent", "<g@x>"),
            "<c@x>": ("child", "<p@x>"),
            "<s@x>": ("solo", "<absent@x>")})
        # select p, c and s; g is deliberately not selected
        self.open_review("R1", [("<p@x>", []), ("<c@x>", []), ("<s@x>", [])])
        _, package, _ = self.export()
        by_id = {item["item_id"]: item for item in package["items"]}
        self.assertEqual([item["item_id"] for item in package["items"]],
                         ["M0001", "M0002", "M0003"])
        mapping = {"<c@x>": "M0001", "<p@x>": "M0002", "<s@x>": "M0003"}
        self.assertEqual(by_id["M0001"]["parent_item_id"], "M0002")  # c -> selected p
        self.assertIsNone(by_id["M0002"]["parent_item_id"])          # p -> unselected g
        self.assertIsNone(by_id["M0003"]["parent_item_id"])          # external parent
        raw = path = self.root / "package.json"
        self.assertNotIn(b"<g@x>", raw.read_bytes())  # no internal IDs leave the vault
        self.assertNotIn(b"<absent@x>", raw.read_bytes())
        self.assertNotIn(b"subject", raw.read_bytes())

    def test_repeated_exports_are_byte_identical_and_input_set_is_frozen(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m1@x>", body="first")
        vault.init(folder, self.db)
        self.open_review("R1", [("<m1@x>", [])])
        first_path, first, _ = self.export(name="p1.json")
        second_path, second, _ = self.export(name="p2.json")
        self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
        self.assertEqual(first, second)
        # later ingestion must not enlarge the registered delivery
        folder2 = self.batch("b2")
        write_eml(folder2, "n.eml", "<m2@x>", body="second",
                  date="Tue, 03 Nov 2026 09:00:00 +0000")
        vault.ingest(folder2, self.db)
        third_path, third, _ = self.export(name="p3.json")
        self.assertEqual(third_path.read_bytes(), first_path.read_bytes())

    def test_existing_output_refused_including_symlink_and_no_half_file(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        self.open_review("R1", [("<m1@x>", [])])
        existing = self.root / "exists.json"
        existing.write_text("KEEP")
        with self.assertRaises(FileExistsError):
            review.review_export(self.db, "R1", existing)
        self.assertEqual(existing.read_text(), "KEEP")
        link = self.root / "link.json"
        link.symlink_to(existing)
        with self.assertRaises(FileExistsError):
            review.review_export(self.db, "R1", link)
        leftovers = [p.name for p in self.root.iterdir()
                     if p.name.startswith(".review-")]
        self.assertEqual(leftovers, [])

    def test_export_fails_after_purge_without_writing_file(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        self.open_review("R1", [("<m1@x>", [])])
        vault.retention_plan(self.db, "P", "2026-11-30T00:00:00Z")
        vault.retention_apply(self.db, "P")
        target = self.root / "after-purge.json"
        with self.assertRaisesRegex(ValueError, "no longer live"):
            review.review_export(self.db, "R1", target)
        self.assertFalse(target.exists())
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith(".")], [])

    def test_export_unknown_review_and_missing_tables(self):
        self.init_messages({"<m1@x>": ("abcdef", None)})
        with self.assertRaisesRegex(ValueError, "unknown review_id"):
            review.review_export(self.db, "NOPE", self.root / "x.json")
        # a vault that never used review features has no review tables
        fresh = self.root / "fresh.sqlite"
        folder = self.batch("b2")
        write_eml(folder, "m.eml", "<m2@x>")
        vault.init(folder, fresh)
        with self.assertRaisesRegex(ValueError, "unknown review_id"):
            review.review_export(fresh, "R1", self.root / "y.json")

    def test_v1_database_rejected_and_untouched(self):
        v1 = self.root / "v1.sqlite"
        v1_build("fixtures/mail", v1)
        digest = hashlib.sha256(v1.read_bytes()).hexdigest()
        valid_spec = self.write_json("spec.json", {"review_id": "R1", "messages": [
            {"message_id": "<planning@example.invalid>", "redactions": []}]})
        with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
            review.review_open(v1, valid_spec)
        with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
            review.review_export(v1, "R1", self.root / "p.json")
        # structurally valid inputs still fail at the vault-format boundary
        base = {"format": "mailroom-review-1", "review_id": "R1", "items": [
            {"item_id": "M0001", "parent_item_id": None, "text": "x"}]}
        package = self.write_json("v1-package.json", {**base, "package_sha256": digest_of(base)})
        feedback = self.write_json("v1-feedback.json", {
            "review_id": "R1", "package_sha256": digest_of(base), "return_id": "T1",
            "annotations": [{"annotation_id": "A1", "item_id": "M0001",
                             "start": 0, "end": 1, "comment": "x"}]})
        with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
            review.review_return(v1, "R1", package, feedback)
        with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
            review.review_notes(v1, "<planning@example.invalid>")
        self.assertEqual(hashlib.sha256(v1.read_bytes()).hexdigest(), digest)
        self.assertFalse((self.root / "p.json").exists())

    def test_missing_vault_is_never_created(self):
        missing = self.root / "missing.sqlite"
        spec = self.write_json("spec.json", {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": []}]})
        # the mutating command uses the same existence guard as other vault writes
        with self.assertRaisesRegex(ValueError, "vault does not exist"):
            review.review_open(missing, spec)
        self.assertFalse(missing.exists())
        # readonly commands follow the established readonly-connect semantics
        with self.assertRaises(sqlite3.OperationalError):
            review.review_export(missing, "R1", self.root / "p.json")
        with self.assertRaises(sqlite3.OperationalError):
            review.review_notes(missing, "<m1@x>")
        self.assertFalse(missing.exists())
        self.assertFalse((self.root / "p.json").exists())


class ReturnTests(ReviewCase):
    def setUp(self):
        super().setUp()
        # body: abcdefXYZghi -> redact [2,6) => ab[REDACTED]XYZghi
        self.bodies = self.init_messages({"<m1@x>": ("abcdefXYZghi", None)})
        self.open_review("R1", [("<m1@x>", [[2, 6]])])
        self.pkg_path, self.package, _ = self.export()

    def feedback(self, return_id, annotations, digest=None):
        value = {"review_id": "R1",
                 "package_sha256": digest or self.package["package_sha256"],
                 "return_id": return_id, "annotations": annotations}
        return self.write_json(f"{return_id}.json", value)

    def test_accepted_annotation_maps_to_exact_source_coordinates(self):
        path = self.feedback("T1", [
            {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "XYZ span"}])
        receipt = review.review_return(self.db, "R1", self.pkg_path, path)
        self.assertEqual(receipt, {
            "review_id": "R1", "return_id": "T1",
            "package_sha256": self.package["package_sha256"],
            "annotation_ids": ["A1"]})
        notes = review.review_notes(self.db, "<m1@x>")["annotations"]
        self.assertEqual(len(notes), 1)
        note = notes[0]
        self.assertEqual((note["delivery_start"], note["delivery_end"]), (12, 15))
        self.assertEqual((note["source_start"], note["source_end"]), (6, 9))
        self.assertEqual(note["comment"], "XYZ span")
        self.assertEqual(set(note), {
            "review_id", "return_id", "annotation_id", "item_id", "source_sha256",
            "body_sha256", "delivery_start", "delivery_end", "source_start",
            "source_end", "comment"})

    def test_endpoint_valid_span_crossing_marker_rejects_whole_feedback(self):
        path = self.feedback("T1", [
            {"annotation_id": "GOOD", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "legal"},
            {"annotation_id": "BAD", "item_id": "M0001", "start": 11, "end": 13,
             "comment": "crosses marker edge"}])
        with self.assertRaisesRegex(ValueError, "touches inserted"):
            review.review_return(self.db, "R1", self.pkg_path, path)
        # nothing from the rejected batch is stored
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(0,)])
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_receipts"), [(0,)])

    def test_span_fully_inside_inserted_marker_rejected(self):
        path = self.feedback("T1", [
            {"annotation_id": "BAD", "item_id": "M0001", "start": 3, "end": 8,
             "comment": "inside marker"}])
        with self.assertRaisesRegex(ValueError, "touches inserted"):
            review.review_return(self.db, "R1", self.pkg_path, path)

    def test_tampered_packages_with_recomputed_digests_are_rejected(self):
        def tamper(mutate, tag):
            broken = json.loads(json.dumps(self.package))
            mutate(broken)
            broken["package_sha256"] = digest_of(
                {k: v for k, v in broken.items() if k != "package_sha256"})
            pkg_path = self.write_json(f"tampered-{tag}.json", broken)
            fb_path = self.feedback(f"T-{tag}", [
                {"annotation_id": f"A-{tag}", "item_id": "M0001",
                 "start": 12, "end": 15, "comment": "x"}],
                digest=broken["package_sha256"])
            with self.assertRaisesRegex(ValueError, "registered delivery"):
                review.review_return(self.db, "R1", pkg_path, fb_path)

        tamper(lambda p: p["items"][0].__setitem__(
            "text", p["items"][0]["text"] + "!"), "text")
        tamper(lambda p: p["items"][0].__setitem__(
            "parent_item_id", "M0009"), "parent")
        tamper(lambda p: p["items"].append(
            dict(p["items"][0]) | {"item_id": "M0002"}), "set")

        # item ordering needs a package with at least two items
        folder = self.batch("order-mail")
        write_eml(folder, "a.eml", "<o1@x>", body="abcdefXYZghi",
                  date="Tue, 03 Nov 2026 08:00:00 +0000")
        write_eml(folder, "b.eml", "<o2@x>", body="second body",
                  date="Tue, 03 Nov 2026 09:00:00 +0000")
        vault.ingest(folder, self.db)
        spec_path = self.write_json("order-spec.json", {"review_id": "RORD", "messages": [
            {"message_id": "<o1@x>", "redactions": [[2, 6]]},
            {"message_id": "<o2@x>", "redactions": []}]})
        review.review_open(self.db, spec_path)
        order_pkg_path, order_pkg, _ = self.export("RORD", "order-package.json")
        reordered = json.loads(json.dumps(order_pkg))
        reordered["items"].reverse()
        reordered["package_sha256"] = digest_of(
            {k: v for k, v in reordered.items() if k != "package_sha256"})
        bad_pkg = self.write_json("tampered-order.json", reordered)
        bad_fb = self.write_json("order-feedback.json", {
            "review_id": "RORD", "package_sha256": reordered["package_sha256"],
            "return_id": "T-order", "annotations": [
                {"annotation_id": "A-order", "item_id": "M0001",
                 "start": 12, "end": 15, "comment": "x"}]})
        with self.assertRaisesRegex(ValueError, "registered delivery"):
            review.review_return(self.db, "RORD", bad_pkg, bad_fb)
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(0,)])

    def test_package_self_digest_mismatch_rejected(self):
        broken = json.loads(json.dumps(self.package))
        broken["package_sha256"] = "0" * 64
        pkg_path = self.write_json("baddigest.json", broken)
        fb_path = self.feedback("T1", [
            {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "x"}], digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "does not match its own content"):
            review.review_return(self.db, "R1", pkg_path, fb_path)

    def test_feedback_digest_binding_and_cross_batch_isolation(self):
        # second batch over the same body also numbers its item M0001; because
        # review_id enters the digest, the two deliveries hash differently
        spec2 = self.write_json("spec2.json", {"review_id": "R2", "messages": [
            {"message_id": "<m1@x>", "redactions": [[2, 6]]}]})
        review.review_open(self.db, spec2)
        pkg2_path, package2, _ = self.export("R2", "package2.json")
        self.assertEqual(package2["items"][0]["item_id"], "M0001")
        self.assertNotEqual(package2["package_sha256"], self.package["package_sha256"])
        annotation = {"annotation_id": "A1", "item_id": "M0001",
                      "start": 12, "end": 15, "comment": "x"}
        r1_feedback = self.feedback("T1", [dict(annotation)])
        # a feedback claiming R2 but carrying R1's package digest cannot bind
        r2_feedback_wrong_digest = self.write_json("r2-wrong.json", {
            "review_id": "R2", "package_sha256": self.package["package_sha256"],
            "return_id": "T1", "annotations": [dict(annotation)]})
        with self.assertRaisesRegex(ValueError, "feedback is not bound"):
            review.review_return(self.db, "R2", pkg2_path, r2_feedback_wrong_digest)
        # R1's package file cannot even be presented as an R2 delivery: its
        # embedded review_id fails structural identity before the vault lookup
        with self.assertRaisesRegex(ValueError, "package review_id does not match"):
            review.review_return(self.db, "R2", self.pkg_path, r1_feedback)
        # batches keep independent annotation namespaces: both may use id "A1"
        fb2 = self.write_json("R2-feedback.json", {
            "review_id": "R2", "package_sha256": package2["package_sha256"],
            "return_id": "T1", "annotations": [
                {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
                 "comment": "second batch"}]})
        review.review_return(self.db, "R2", pkg2_path, fb2)
        notes = review.review_notes(self.db, "<m1@x>")["annotations"]
        self.assertEqual([(n["review_id"], n["comment"]) for n in notes],
                         [("R2", "second batch")])  # R1 has not been accepted yet
        review.review_return(self.db, "R1", self.pkg_path, r1_feedback)
        notes = review.review_notes(self.db, "<m1@x>")["annotations"]
        self.assertEqual([n["review_id"] for n in notes], ["R1", "R2"])  # sorted

    def test_item_mapping_does_not_carry_across_batches_with_different_items(self):
        # R2 selects a different message set; its M0001 points at another source
        folder = self.batch("more")
        write_eml(folder, "other.eml", "<other@x>", body="abcdefXYZghi",
                  date="Tue, 03 Nov 2026 09:00:00 +0000")
        vault.ingest(folder, self.db)
        spec2 = self.write_json("spec-other.json", {"review_id": "R2", "messages": [
            {"message_id": "<other@x>", "redactions": [[2, 6]]}]})
        review.review_open(self.db, spec2)
        pkg2_path, package2, _ = self.export("R2", "package-other.json")
        # an R1-style annotation on R2's M0001 maps onto <other@x>, not <m1@x>
        fb = self.write_json("other-feedback.json", {
            "review_id": "R2", "package_sha256": package2["package_sha256"],
            "return_id": "T1", "annotations": [
                {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
                 "comment": "lands on the other source"}]})
        review.review_return(self.db, "R2", pkg2_path, fb)
        other_notes = review.review_notes(self.db, "<other@x>")["annotations"]
        self.assertEqual(len(other_notes), 1)
        self.assertEqual(other_notes[0]["review_id"], "R2")
        self.assertEqual(other_notes[0]["item_id"], "M0001")
        self.assertEqual(review.review_notes(self.db, "<m1@x>")["annotations"], [])

    def test_annotation_id_conflicts_across_returns_reject_entire_batch(self):
        first = self.feedback("T1", [
            {"annotation_id": "SHARED", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "first"}])
        review.review_return(self.db, "R1", self.pkg_path, first)
        second = self.feedback("T2", [
            {"annotation_id": "OTHER", "item_id": "M0001", "start": 0, "end": 2,
             "comment": "fine alone"},
            {"annotation_id": "SHARED", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "conflicting id even with identical span"}])
        with self.assertRaisesRegex(ValueError, "already used by another return"):
            review.review_return(self.db, "R1", self.pkg_path, second)
        ids = [r[0] for r in self.query(
            "SELECT annotation_id FROM vault_review_annotations ORDER BY annotation_id")]
        self.assertEqual(ids, ["SHARED"])  # the fine item was not swallowed in

    def test_replay_returns_first_receipt_and_tolerates_reordering(self):
        annotations = [
            {"annotation_id": "A2", "item_id": "M0001", "start": 0, "end": 2,
             "comment": "ab"},
            {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "XYZ"}]
        first = self.feedback("T1", annotations)
        receipt = review.review_return(self.db, "R1", self.pkg_path, first)
        shuffled = self.feedback("T1b", list(reversed(annotations)))
        # same return_id file content re-keyed name; return_id stays T1
        shuffled_value = json.loads(shuffled.read_text())
        shuffled_value["return_id"] = "T1"
        shuffled_path = self.write_json("T1-reordered.json", shuffled_value)
        self.assertEqual(
            review.review_return(self.db, "R1", self.pkg_path, shuffled_path), receipt)
        # changed content under the same return_id is refused
        changed_value = json.loads(first.read_text())
        changed_value["annotations"][0]["comment"] = "changed"
        with self.assertRaisesRegex(ValueError, "already accepted with different feedback"):
            review.review_return(self.db, "R1", self.pkg_path,
                                 self.write_json("T1-changed.json", changed_value))
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(2,)])
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_receipts"), [(1,)])

    def test_replay_after_purge_returns_receipt_but_new_return_fails(self):
        first = self.feedback("T1", [
            {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
             "comment": "before purge"}])
        receipt = review.review_return(self.db, "R1", self.pkg_path, first)
        vault.retention_plan(self.db, "P", "2026-11-30T00:00:00Z")
        vault.retention_apply(self.db, "P")
        # the accepted return still replays with the original receipt
        self.assertEqual(
            review.review_return(self.db, "R1", self.pkg_path, first), receipt)
        # a brand-new return_id cannot land new annotations once a source is purged
        new = self.feedback("T2", [
            {"annotation_id": "A2", "item_id": "M0001", "start": 0, "end": 2,
             "comment": "after purge"}])
        with self.assertRaisesRegex(ValueError, "no longer live"):
            review.review_return(self.db, "R1", self.pkg_path, new)
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(1,)])

    def test_strict_structure_validation(self):
        def must_fail(value, pattern):
            path = self.write_json("structure.json", value)
            with self.assertRaisesRegex(ValueError, pattern):
                review.review_return(self.db, "R1", self.pkg_path, path)

        good_annotation = {"annotation_id": "A1", "item_id": "M0001",
                           "start": 12, "end": 15, "comment": "ok"}
        base = {"review_id": "R1", "package_sha256": self.package["package_sha256"],
                "return_id": "T1", "annotations": [dict(good_annotation)]}
        must_fail({**base, "extra": 1}, "exactly these keys")
        must_fail({**base, "review_id": "OTHER"}, "review_id does not match")
        must_fail({**base, "return_id": ".bad"}, "must match")
        must_fail({**base, "annotations": []}, "1..1000")
        duplicate = json.loads(json.dumps(base))
        duplicate["annotations"].append(dict(good_annotation))
        must_fail(duplicate, "duplicate annotation_id")
        blank = json.loads(json.dumps(base))
        blank["annotations"][0]["comment"] = "   "
        must_fail(blank, "non-blank")
        long_comment = json.loads(json.dumps(base))
        long_comment["annotations"][0]["comment"] = "x" * 2001
        must_fail(long_comment, "2000 code points")
        boolean = json.loads(json.dumps(base))
        boolean["annotations"][0]["start"] = False
        must_fail(boolean, "integer")
        out_of_range = json.loads(json.dumps(base))
        out_of_range["annotations"][0]["end"] = 999
        must_fail(out_of_range, "delivered text length")
        unknown_item = json.loads(json.dumps(base))
        unknown_item["annotations"][0]["item_id"] = "M9999"
        path = self.write_json("unknown-item.json", unknown_item)
        with self.assertRaisesRegex(ValueError, "unknown item_id"):
            review.review_return(self.db, "R1", self.pkg_path, path)

    def test_unknown_review_and_missing_review_tables(self):
        # package and feedback review_id must match the requested id structurally;
        # only then can the unknown batch be detected in the vault
        base = {"format": "mailroom-review-1", "review_id": "NOPE", "items": [
            {"item_id": "M0001", "parent_item_id": None, "text": "x"}]}
        other_pkg = self.write_json("other-package.json",
                                    {**base, "package_sha256": digest_of(base)})
        other_fb = self.write_json("other-feedback.json", {
            "review_id": "NOPE", "package_sha256": digest_of(base),
            "return_id": "T1", "annotations": [
                {"annotation_id": "A1", "item_id": "M0001", "start": 0, "end": 1,
                 "comment": "x"}]})
        with self.assertRaisesRegex(ValueError, "unknown review_id"):
            review.review_return(self.db, "NOPE", other_pkg, other_fb)

    def test_injected_transaction_failure_leaves_no_partial_batch(self):
        annotations = [
            {"annotation_id": f"A{n}", "item_id": "M0001",
             "start": 12, "end": 15, "comment": f"comment {n}"} for n in range(5)]
        path = self.feedback("T1", annotations)
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.lstrip().upper().startswith(
                        "INSERT INTO VAULT_REVIEW_RECEIPTS"):
                    raise sqlite3.OperationalError("injected crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect",
                        side_effect=lambda *a, **k: real_connect(
                            *a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                review.review_return(self.db, "R1", self.pkg_path, path)
        # simulate a restart: reopen the vault and confirm no half batch exists
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(0,)])
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_receipts"), [(0,)])
        # the identical feedback can now be submitted successfully
        receipt = review.review_return(self.db, "R1", self.pkg_path, path)
        self.assertEqual(receipt["annotation_ids"], [f"A{n}" for n in range(5)])
        self.assertEqual(self.query("SELECT count(*) FROM vault_review_annotations"), [(5,)])


class NotesTests(ReviewCase):
    def test_notes_sorting_empty_result_and_unknown_identity(self):
        self.init_messages({"<m1@x>": ("abcdefXYZghi", None),
                            "<m2@x>": ("second body", None)})
        self.open_review("R1", [("<m1@x>", [[2, 6]])])
        pkg_path, package, _ = self.export()
        for index, (start, end) in enumerate(((12, 15), (0, 2))):
            fb = self.write_json(f"fb{index}.json", {
                "review_id": "R1", "package_sha256": package["package_sha256"],
                "return_id": f"T{index}", "annotations": [
                    {"annotation_id": f"A{index}", "item_id": "M0001",
                     "start": start, "end": end, "comment": f"c{index}"}]})
            review.review_return(self.db, "R1", pkg_path, fb)
        # existing identity without annotations returns an empty array
        empty = review.review_notes(self.db, "<m2@x>")
        self.assertEqual(empty, {"message_id": "<m2@x>", "annotations": []})
        with self.assertRaisesRegex(ValueError, "unknown message ID"):
            review.review_notes(self.db, "<ghost@x>")
        result = review.review_notes(self.db, "<m1@x>")
        self.assertEqual([(a["return_id"], a["annotation_id"])
                          for a in result["annotations"]],
                         [("T0", "A0"), ("T1", "A1")])  # sorted

    def test_notes_survive_purge_and_never_carry_payload(self):
        self.init_messages({"<m1@x>": ("abcdefXYZghi", None)})
        self.open_review("R1", [("<m1@x>", [[2, 6]])])
        pkg_path, package, _ = self.export()
        fb = self.write_json("fb.json", {
            "review_id": "R1", "package_sha256": package["package_sha256"],
            "return_id": "T1", "annotations": [
                {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
                 "comment": "XYZ"}]})
        review.review_return(self.db, "R1", pkg_path, fb)
        vault.retention_plan(self.db, "P", "2026-11-30T00:00:00Z")
        vault.retention_apply(self.db, "P")
        result = review.review_notes(self.db, "<m1@x>")
        self.assertEqual(len(result["annotations"]), 1)
        note = result["annotations"][0]
        self.assertEqual((note["source_start"], note["source_end"]), (6, 9))
        joined = json.dumps(note)
        self.assertNotIn("abcdef", joined)  # no body excerpt or payload
        self.assertNotIn("subject", joined)

    def test_notes_creates_no_tables_and_is_readonly(self):
        folder = self.batch("b1")
        write_eml(folder, "m.eml", "<m1@x>")
        vault.init(folder, self.db)
        digest = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.assertEqual(
            review.review_notes(self.db, "<m1@x>"),
            {"message_id": "<m1@x>", "annotations": []})
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.query(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'vault_review%'"), [(0,)])


class FixtureDemoTests(ReviewCase):
    def test_synthetic_fixture_end_to_end_with_golden_digest(self):
        result = vault.init("fixtures/review/batch1", self.db)
        self.assertEqual(result["inserted"], [
            "<review-a@example.invalid>", "<review-b@example.invalid>",
            "<review-c@example.invalid>"])
        summary = review.review_open(self.db, "fixtures/review/spec.json")
        self.assertEqual(summary, {"review_id": "EXTREV-1", "item_count": 3})
        pkg_path = self.root / "package.json"
        export_summary = review.review_export(self.db, "EXTREV-1", pkg_path)
        package = json.loads(pkg_path.read_text())
        golden = "d4804e6ea4a60f40a5099abd567d8e098ca1e80e713ece7e1f0381771483ee35"
        self.assertEqual(package["package_sha256"], golden)
        self.assertEqual(export_summary["package_sha256"], golden)
        # redaction semantics on the fixture bodies
        self.assertEqual(package["items"][0]["text"],
                         "Harbor alpha: budget[REDACTED] [REDACTED] wharf works.\n")
        self.assertEqual(package["items"][1]["text"],
                         "Harbor beta: budget[REDACTED] — crane works. 日本語\n")
        # c's unselected external parent must not appear anywhere
        self.assertNotIn(b"unselected-grandparent", pkg_path.read_bytes())
        receipt = review.review_return(
            self.db, "EXTREV-1", pkg_path, "fixtures/review/feedback.json")
        self.assertEqual(receipt, {
            "review_id": "EXTREV-1", "return_id": "RETURN-1",
            "package_sha256": golden,
            "annotation_ids": ["ANN-CRANE", "ANN-JP", "ANN-LITERAL"]})
        notes_a = review.review_notes(self.db, "<review-a@example.invalid>")["annotations"]
        notes_b = review.review_notes(self.db, "<review-b@example.invalid>")["annotations"]
        # literal [REDACTED] kept in the body maps back to its own source span
        self.assertEqual([(n["delivery_start"], n["delivery_end"],
                          n["source_start"], n["source_end"]) for n in notes_a],
                         [(31, 41, 26, 36)])
        # Unicode annotation and ordinary word annotation after a marker
        self.assertEqual([(n["annotation_id"], n["source_start"], n["source_end"])
                          for n in notes_b],
                         [("ANN-CRANE", 27, 32), ("ANN-JP", 40, 43)])
        # review tables hold no source payload
        review_dump = "\n".join(str(r) for r in self.query(
            "SELECT comment,intervals,document,feedback_canonical "
            "FROM vault_review_annotations, vault_review_items, vault_review_receipts"))
        self.assertNotIn("Harbor alpha", review_dump)


class CliTests(ReviewCase):
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

    def test_full_cli_flow_exit_codes(self):
        folder = self.batch("mail")
        write_eml(folder, "m.eml", "<m1@x>", body="abcdefXYZghi")
        spec = self.write_json("spec.json", {"review_id": "R1", "messages": [
            {"message_id": "<m1@x>", "redactions": [[2, 6]]}]})
        code, out, _ = self.run_cli("vault-init", "--source", str(folder),
                                    "--db", str(self.db))
        self.assertEqual(code, 0)
        code, out, _ = self.run_cli("review-open", "--db", str(self.db),
                                    "--spec", str(spec))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"review_id": "R1", "item_count": 1})
        package = self.root / "package.json"
        code, _, _ = self.run_cli("review-export", "--db", str(self.db),
                                  "--review-id", "R1", "--output", str(package))
        self.assertEqual(code, 0)
        pkg = json.loads(package.read_text())
        feedback = self.write_json("feedback.json", {
            "review_id": "R1", "package_sha256": pkg["package_sha256"],
            "return_id": "T1", "annotations": [
                {"annotation_id": "A1", "item_id": "M0001", "start": 12, "end": 15,
                 "comment": "XYZ"}]})
        code, out, _ = self.run_cli("review-return", "--db", str(self.db),
                                    "--review-id", "R1", "--package", str(package),
                                    "--feedback", str(feedback))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["annotation_ids"], ["A1"])
        code, out, _ = self.run_cli("review-notes", "--db", str(self.db),
                                    "--message-id", "<m1@x>")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["annotations"][0]["source_start"], 6)
        # failure path exits 2
        code, _, err = self.run_cli("review-export", "--db", str(self.db),
                                    "--review-id", "NOPE",
                                    "--output", str(self.root / "x.json"))
        self.assertEqual(code, 2)
        self.assertIn("unknown review_id", err)
        code, _, err = self.run_cli("review-notes", "--db", str(self.db),
                                    "--message-id", "<missing@x>")
        self.assertEqual(code, 2)
        self.assertIn("unknown message ID", err)


if __name__ == "__main__":
    unittest.main()
