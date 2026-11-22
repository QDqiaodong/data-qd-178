"""Offline attachment indicator investigation and forensic delivery tests.

The expected values are built independently of the module under test: ZIP
ordering, physical identities, paths and content digests are constructed with
the standard library and asserted explicitly rather than derived from the
investigation output.
"""
import contextlib
import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import tracemalloc
import unittest
import zipfile
import zlib
from email.message import EmailMessage
from pathlib import Path
from unittest import mock

from mailroom import cli, investigate, recovery, vault
from mailroom.archive import build as v1_build

CANONICAL_KW = dict(ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False)
A = "<msg-a@example.invalid>"
B = "<msg-b@example.invalid>"
C = "<msg-c@example.invalid>"
X = "<msg-x@example.invalid>"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, **CANONICAL_KW).encode("utf-8")


def _central_header_offset(raw, info):
    """Locate the central directory record for one ZipInfo by signature scan."""
    import struct
    cursor = 0
    while cursor < len(raw) - 4:
        sig = struct.unpack_from("<I", raw, cursor)[0]
        if sig == 0x02014B50:
            name_len = struct.unpack_from("<H", raw, cursor + 28)[0]
            extra_len = struct.unpack_from("<H", raw, cursor + 30)[0]
            comment_len = struct.unpack_from("<H", raw, cursor + 32)[0]
            name = bytes(raw[cursor + 46:cursor + 46 + name_len])
            if name == info.filename.encode("utf-8", "surrogateescape"):
                return cursor
            cursor += 46 + name_len + extra_len + comment_len
        else:
            cursor += 1
    raise AssertionError("central header not found")


def make_zip(entries, fail_crc=(), encrypted=(), symlinks=()):
    """Build a ZIP from (name, data[, method]) entries in the given order.

    ``fail_crc`` names keep their original CRC-32 header but get one byte of
    the stored stream flipped, so a full read reaches EOF yet fails the CRC;
    ``encrypted`` names carry the PKWARE encryption flag (no real encryption is
    needed); names in ``symlinks`` carry the Unix symlink external attribute.
    Directory names end with '/'.
    """
    fail_crc = set(fail_crc)
    encrypted = set(encrypted)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            name, data = entry[0], entry[1]
            method = entry[2] if len(entry) > 2 else zipfile.ZIP_DEFLATED
            info = zipfile.ZipInfo(name)
            info.compress_type = method
            if name in symlinks:
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, data)
    raw = bytearray(buf.getvalue())
    with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
        offsets = {info.filename: (info.header_offset, info.compress_size,
                                   info) for info in zf.infolist()}
    for name in encrypted:
        # writestr clears the encryption flag, so set general-purpose bit 0 in
        # both the local header (offset 6) and central header (offset 8).
        header_offset, _, info = offsets[name]
        raw[header_offset + 6] |= 0x01
        central = _central_header_offset(raw, info)
        raw[central + 8] |= 0x01
    if fail_crc:
        with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
            offsets = {info.filename: (info.header_offset, info.compress_size)
                       for info in zf.infolist()}
        for name in fail_crc:
            header_offset, compress_size = offsets[name]
            # Local header is 30 fixed bytes plus the filename and extra fields.
            with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
                info = zf.getinfo(name)
            data_start = header_offset + 30 + len(info.filename.encode()) \
                + len(info.extra)
            if compress_size == 0:
                raise AssertionError("cannot corrupt a zero-length member")
            raw[data_start] ^= 0xFF
    return bytes(raw)


def make_zip_with_oversize_directory():
    """A directory entry whose declared uncompressed length is nonzero.

    zipfile itself refuses to serialise this, so the local and central headers
    are written byte-by-byte with the standard library struct primitives.
    """
    import struct
    name = b"dir/"
    crc = zlib.crc32(b"") & 0xFFFFFFFF
    declared_size = 7
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc,
                        declared_size, declared_size, len(name), 0) + name
    # central: sig, version-made, version-needed, flags, method, time, date,
    # crc, comp size, uncomp size, name len, extra len, comment len, disk,
    # internal attrs, external attrs, local header offset.
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0,
                          0, crc, declared_size, declared_size, len(name), 0,
                          0, 0, 0, 0, 0) + name
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central),
                      len(local), 0)
    return local + central + end


def make_eml(msg_id, attachments, parent=None, body="plain body",
             date="Tue, 03 Nov 2026 08:00:00 +0000"):
    msg = EmailMessage()
    msg["From"] = "a@example.invalid"
    msg["To"] = "b@example.invalid"
    msg["Date"] = date
    msg["Message-ID"] = msg_id
    if parent:
        msg["In-Reply-To"] = parent
    msg["Subject"] = "case"
    msg.set_content(body)
    for filename, data, ctype in attachments:
        main, sub = ctype.split("/", 1)
        msg.add_attachment(data, maintype=main, subtype=sub, filename=filename)
    return bytes(msg)


def limits(**overrides):
    base = {"max_depth": 4, "max_members": 2000,
            "max_expanded_bytes": 1_073_741_824}
    base.update(overrides)
    return base


class InvestigateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"

    def write_mail(self, messages):
        folder = self.root / "mail"
        folder.mkdir(exist_ok=True)
        for name, raw in messages.items():
            (folder / name).write_bytes(raw)
        if self.db.exists():
            vault.ingest(folder, self.db)
        else:
            vault.init(folder, self.db)
        return folder

    def write_spec(self, messages, indicators, lim=None, name="spec.json",
                   raw=None):
        path = self.root / name
        if raw is None:
            raw = canonical({"messages": messages, "indicators": indicators,
                             "limits": lim or limits()})
        path.write_bytes(raw)
        return path

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv",
                               ["mail-archive", *[str(a) for a in argv]]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def investigate(self, messages, indicators, lim=None, name="report.json"):
        spec = self.write_spec(messages, indicators, lim)
        report = self.root / name
        result = investigate.investigate(self.db, spec, report)
        return result, report, json.loads(report.read_bytes())

    def roots_by(self, report):
        return {(r["message_id"], r["part"]): r for r in report["roots"]}

    def table_fingerprint(self):
        con = sqlite3.connect(self.db)
        try:
            digest = hashlib.sha256()
            for name, in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "ORDER BY name"):
                for row in con.execute(f'SELECT * FROM "{name}" ORDER BY rowid'):
                    digest.update(repr(row).encode())
            return digest.hexdigest()
        finally:
            con.close()


class BasicInvestigationTests(InvestigateCase):
    def test_three_physical_occurrences_single_blob_and_labels_only(self):
        hit = b"indicator leaf content"
        hit_digest = sha(hit)
        decoy = b"different bytes sharing the member name"
        # The nested container holds the same hit content under the same name.
        inner = make_zip([("../dup.txt", hit), ("abs/plain.txt", b"noise")])
        root_zip = make_zip([
            ("../dup.txt", hit),                  # member 1: first hit
            ("inner.zip", inner),                 # member 2: nested second hit
            ("../dup.txt", decoy),                # member 3: same name, no hit
            ("/etc/absolute.bin", b"unmatched"),  # absolute label, not delivered
        ])
        eml_a = make_eml(A, [("case.zip", root_zip, "application/zip")])
        eml_b = make_eml(B, [("loose.bin", hit, "application/octet-stream")])
        self.write_mail({"a.eml": eml_a, "b.eml": eml_b})
        result, report_path, report = self.investigate([A, B], [hit_digest])
        self.assertEqual(set(result), {"vault", "sha256", "bytes"})
        self.assertEqual(result["sha256"], sha(report_path.read_bytes()))
        self.assertEqual(result["bytes"], len(report_path.read_bytes()))
        self.assertEqual(report["format"], "mailroom-attachment-report-1")
        self.assertEqual(report["spec"]["messages"], [A, B])
        self.assertEqual(report["spec"]["indicators"], [hit_digest])
        root_a = self.roots_by(report)[(A, 2)]
        self.assertEqual(root_a["status"], "matched")
        self.assertIsNone(root_a["issue"])
        # Independent oracle: paths come from central-directory positions and
        # the two same-named leaves keep distinct physical identities.
        expected_leaves = [
            ([1], "../dup.txt", True),
            ([2, 1], "../dup.txt", True),
            ([2, 2], "abs/plain.txt", False),
            ([3], "../dup.txt", False),
            ([4], "/etc/absolute.bin", False),
        ]
        self.assertEqual([(l["path"], l["filename"], l["matched"])
                          for l in root_a["leaves"]], expected_leaves)
        root_b = self.roots_by(report)[(B, 2)]
        self.assertEqual([(l["path"], l["matched"]) for l in root_b["leaves"]],
                         [([], True)])
        occurrences = [(r["message_id"], l["path"]) for r in report["roots"]
                       for l in r["leaves"] if l["matched"]]
        self.assertEqual(occurrences, [(A, [1]), (A, [2, 1]), (B, [])])

        delivery = self.root / "delivery"
        delivered = investigate.deliver(self.db, report_path, result["sha256"],
                                        delivery)
        self.assertEqual(set(delivered), {"vault", "report_sha256",
                                          "blob_count", "occurrence_count"})
        self.assertEqual(delivered["blob_count"], 1)
        self.assertEqual(delivered["occurrence_count"], 3)
        self.assertEqual(sorted(p.name for p in (delivery / "blobs").iterdir()),
                         [hit_digest])
        self.assertEqual((delivery / "blobs" / hit_digest).read_bytes(), hit)
        manifest = json.loads((delivery / "manifest.json").read_bytes())
        self.assertEqual(manifest["format"], "mailroom-attachment-delivery-1")
        self.assertEqual(manifest["blobs"],
                         [{"sha256": hit_digest, "size_bytes": len(hit)}])
        self.assertEqual([(o["message_id"], o["part"], o["path"])
                          for o in manifest["occurrences"]],
                         [(A, 2, [1]), (A, 2, [2, 1]), (B, 2, [])])
        # Only the prescribed delivery paths exist; member names are labels and
        # neither the outer ZIP nor unmatched siblings cross the boundary.
        self.assertEqual(sorted(p.name for p in delivery.iterdir()),
                         ["blobs", "manifest.json"])
        self.assertEqual(len(list((delivery / "blobs").iterdir())), 1)

    def test_symlink_attribute_member_is_treated_as_ordinary_data(self):
        hit = b"symlink-labeled data"
        root_zip = make_zip([("link.bin", hit)], symlinks=("link.bin",))
        self.write_mail({"a.eml": make_eml(A, [("a.zip", root_zip,
                                                "application/zip")])})
        _, report_path, report = self.investigate([A], [sha(hit)])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "matched")
        delivery = self.root / "delivery"
        investigate.deliver(self.db, report_path,
                            sha(report_path.read_bytes()), delivery)
        self.assertEqual(sorted(p.name for p in delivery.iterdir()),
                         ["blobs", "manifest.json"])
        self.assertEqual((delivery / "blobs" / sha(hit)).read_bytes(), hit)

    def test_application_zip_without_zip_extension_is_still_a_container(self):
        hit = b"container without extension"
        root_zip = make_zip([("leaf.dat", hit)])
        self.write_mail({"a.eml": make_eml(
            A, [("container.dat", root_zip, "application/zip")])})
        _, _, report = self.investigate([A], [sha(hit)])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "matched")
        self.assertEqual([l["path"] for l in root["leaves"]], [[1]])

    def test_zip_extension_leaf_with_other_media_type_is_a_container(self):
        root_zip = make_zip([("leaf.dat", b"x")])
        self.write_mail({"a.eml": make_eml(
            A, [("named.zip", root_zip, "application/octet-stream")])})
        _, _, report = self.investigate([A], [sha(b"x")])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "matched")
        self.assertEqual(root["leaves"][0]["sha256"], sha(b"x"))

    def test_empty_zip_empty_leaf_no_attachment_and_no_hits(self):
        empty_zip = make_zip([])
        empty_leaf = b""
        no_attach = make_eml(C, [])
        self.write_mail({
            "z.eml": make_eml(A, [("empty.zip", empty_zip, "application/zip")]),
            "l.eml": make_eml(B, [("empty.bin", empty_leaf,
                                   "application/octet-stream")]),
            "n.eml": no_attach,
        })
        _, report_path, report = self.investigate([A, B, C], [sha(b"target")])
        roots = self.roots_by(report)
        self.assertEqual(roots[(A, 2)]["status"], "clear")
        self.assertEqual(roots[(A, 2)]["leaves"], [])
        empty_root = roots[(B, 2)]
        self.assertEqual(empty_root["status"], "clear")
        self.assertEqual(empty_root["leaves"][0]["size_bytes"], 0)
        self.assertEqual(empty_root["leaves"][0]["sha256"], sha(b""))
        self.assertNotIn((C, 2), roots)
        self.assertEqual([m["message_id"] for m in report["messages"]],
                         [A, B, C])
        # An empty but complete report delivers an empty manifest and blobs/.
        delivery = self.root / "delivery"
        result = investigate.deliver(self.db, report_path,
                                     sha(report_path.read_bytes()), delivery)
        self.assertEqual(result["blob_count"], 0)
        self.assertEqual(result["occurrence_count"], 0)
        manifest = json.loads((delivery / "manifest.json").read_bytes())
        self.assertEqual(manifest["blobs"], [])
        self.assertEqual(manifest["occurrences"], [])
        self.assertTrue((delivery / "blobs").is_dir())

    def test_empty_leaf_can_match_an_indicator(self):
        self.write_mail({"l.eml": make_eml(
            A, [("empty.bin", b"", "application/octet-stream")])})
        _, report_path, report = self.investigate([A], [sha(b"")])
        self.assertEqual(self.roots_by(report)[(A, 2)]["status"], "matched")
        delivery = self.root / "delivery"
        investigate.deliver(self.db, report_path,
                            sha(report_path.read_bytes()), delivery)
        self.assertTrue((delivery / "blobs" / sha(b"")).is_file())

    def test_canonical_report_encoding_and_stdout_contract(self):
        self.write_mail({"a.eml": make_eml(
            A, [("f.bin", b"data", "application/octet-stream")])})
        spec = self.write_spec([A], [sha(b"nope")])
        report_path = self.root / "report.json"
        result = investigate.investigate(self.db, spec, report_path)
        raw = report_path.read_bytes()
        self.assertFalse(raw.endswith(b"\n"))
        document = json.loads(raw)
        self.assertEqual(raw, canonical(document))
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_attachment_disposition_without_filename_is_an_attachment(self):
        # Mirrors the parse.py rule: Content-Disposition: attachment alone,
        # even with a null filename, makes the part a top-level leaf.
        message = EmailMessage()
        message["From"] = "a@example.invalid"
        message["To"] = "b@example.invalid"
        message["Date"] = "Tue, 03 Nov 2026 08:00:00 +0000"
        message["Message-ID"] = A
        message["Subject"] = "case"
        message.set_content("body")
        message.add_attachment(b"nameless bytes", maintype="application",
                               subtype="octet-stream", filename=None)
        self.write_mail({"a.eml": bytes(message)})
        _, _, report = self.investigate([A], [sha(b"nameless bytes")])
        root = self.roots_by(report)[(A, 2)]
        self.assertIsNone(root["filename"])
        self.assertEqual(root["status"], "matched")
        self.assertEqual(root["leaves"][0]["filename"], None)

    def test_report_rejects_whitespace_variant_only_when_hash_is_wrong(self):
        self.write_mail({"a.eml": make_eml(
            A, [("f.bin", b"data", "application/octet-stream")])})
        spec = self.write_spec([A], [sha(b"data")])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        document = json.loads(report_path.read_bytes())
        # Different whitespace changes the file bytes: the trusted hash must
        # reject it, although the logical structure would still parse.
        pretty = (json.dumps(document, indent=2) + "\n").encode()
        pretty_path = self.root / "pretty.json"
        pretty_path.write_bytes(pretty)
        with self.assertRaisesRegex(ValueError, "approved digest"):
            investigate.deliver(self.db, pretty_path, approved["sha256"],
                                self.root / "delivery")
        # The same pretty bytes deliver when the operator approves their hash.
        ok = investigate.deliver(self.db, pretty_path, sha(pretty),
                                 self.root / "delivery-pretty")
        self.assertEqual(ok["occurrence_count"], 1)


class IndeterminateTests(InvestigateCase):
    def test_crc_corruption_after_a_hit_keeps_hit_but_blocks_delivery(self):
        hit = b"first verified hit"
        root_zip = make_zip([("hit.bin", hit), ("broken.bin", b"later bytes")],
                            fail_crc=("broken.bin",))
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        _, report_path, report = self.investigate([A], [sha(hit)])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "indeterminate")
        self.assertEqual(root["issue"], {"path": [2], "reason": "invalid_zip"})
        self.assertEqual([(l["path"], l["matched"]) for l in root["leaves"]],
                         [([1], True)])
        delivery = self.root / "delivery"
        with self.assertRaisesRegex(ValueError, "not fully investigated"):
            investigate.deliver(self.db, report_path,
                                sha(report_path.read_bytes()), delivery)
        self.assertFalse(delivery.exists())

    def test_encrypted_member_is_indeterminate_not_clear_even_without_hits(self):
        root_zip = make_zip([("secret.bin", b"ciphertext")],
                            encrypted=("secret.bin",))
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        _, _, report = self.investigate([A], [sha(b"absent")])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "indeterminate")
        self.assertEqual(root["issue"]["reason"], "encrypted")
        self.assertEqual(root["leaves"], [])

    def test_unsupported_compression_is_classified(self):
        root_zip = make_zip([("m.bin", b"data", zipfile.ZIP_BZIP2)])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        _, _, report = self.investigate([A], [sha(b"x")])
        self.assertEqual(self.roots_by(report)[(A, 2)]["issue"],
                         {"path": [1], "reason": "unsupported_compression"})

    def test_root_zip_that_cannot_open_is_invalid_zip_with_empty_path(self):
        self.write_mail({"a.eml": make_eml(
            A, [("broken.zip", b"not a zip at all", "application/zip")])})
        _, _, report = self.investigate([A], [sha(b"x")])
        root = self.roots_by(report)[(A, 2)]
        self.assertEqual(root["status"], "indeterminate")
        self.assertEqual(root["issue"], {"path": [], "reason": "invalid_zip"})
        self.assertEqual(root["leaves"], [])

    def test_nested_container_that_cannot_open_is_invalid_zip_at_member_path(self):
        root_zip = make_zip([("inner.zip", b"broken container bytes")])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        _, _, report = self.investigate([A], [sha(b"x")])
        self.assertEqual(self.roots_by(report)[(A, 2)]["issue"],
                         {"path": [1], "reason": "invalid_zip"})

    def test_directory_with_nonzero_declared_size_is_invalid_zip(self):
        raw_zip = make_zip_with_oversize_directory()
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", raw_zip, "application/zip")])})
        _, _, report = self.investigate([A], [sha(b"x")])
        self.assertEqual(self.roots_by(report)[(A, 2)]["issue"],
                         {"path": [1], "reason": "invalid_zip"})

    def test_indeterminate_root_does_not_block_other_roots_report(self):
        good_hit = b"good hit"
        good_zip = make_zip([("g.bin", good_hit)])
        bad_zip = make_zip([("s.bin", b"secret")], encrypted=("s.bin",))
        self.write_mail({
            "a.eml": make_eml(A, [("good.zip", good_zip, "application/zip"),
                                  ("bad.zip", bad_zip, "application/zip")]),
        })
        _, report_path, report = self.investigate([A], [sha(good_hit)])
        roots = report["roots"]
        self.assertEqual([r["part"] for r in roots], [2, 3])
        self.assertEqual(roots[0]["status"], "matched")
        self.assertEqual(roots[1]["status"], "indeterminate")
        with self.assertRaisesRegex(ValueError, "not fully investigated"):
            investigate.deliver(self.db, report_path,
                                sha(report_path.read_bytes()),
                                self.root / "delivery")


class BudgetTests(InvestigateCase):
    def test_duplicate_nested_zip_charges_each_physical_appearance(self):
        hit = b"repeated container content"
        inner = make_zip([("hit.bin", hit), ("pad.bin", b"0" * 100)])
        # The same inner ZIP bytes appear twice; no digest cache may share them.
        root_zip = make_zip([("one.zip", inner), ("two.zip", inner)])
        inner_size = len(inner)
        expanded = inner_size + len(hit) + 100  # first appearance fully fits
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(hit)],
                               limits(max_expanded_bytes=expanded))
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        report = json.loads(report_path.read_bytes())
        root = self.roots_by(report)[(A, 2)]
        # The second appearance re-charges the nested container's own bytes.
        self.assertEqual(root["status"], "indeterminate")
        self.assertEqual(root["issue"]["reason"], "byte_limit")
        self.assertEqual(root["issue"]["path"][0], 2)
        # First appearance's complete leaves remain honest findings.
        self.assertTrue(any(l["path"] == [1, 1] and l["matched"]
                            for l in root["leaves"]))

    def test_byte_limit_equality_boundary_and_one_byte_over(self):
        leaf = b"abcdefghij"  # 10 decompressed bytes
        root_zip = make_zip([("leaf.bin", leaf)])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(leaf)],
                               limits(max_expanded_bytes=10))
        ok_path = self.root / "ok.json"
        investigate.investigate(self.db, spec, ok_path)
        self.assertEqual(self.roots_by(json.loads(ok_path.read_bytes()))[(A, 2)]
                         ["status"], "matched")
        spec9 = self.write_spec([A], [sha(leaf)],
                                limits(max_expanded_bytes=9), name="spec9.json")
        over_path = self.root / "over.json"
        investigate.investigate(self.db, spec9, over_path)
        root = self.roots_by(json.loads(over_path.read_bytes()))[(A, 2)]
        self.assertEqual(root["issue"], {"path": [1], "reason": "byte_limit"})
        self.assertEqual(root["leaves"], [])

    def test_top_level_leaf_byte_budget_uses_empty_path(self):
        leaf = b"x" * 5
        self.write_mail({"a.eml": make_eml(
            A, [("leaf.bin", leaf, "application/octet-stream")])})
        spec = self.write_spec([A], [sha(leaf)],
                               limits(max_expanded_bytes=4))
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        root = self.roots_by(json.loads(report_path.read_bytes()))[(A, 2)]
        self.assertEqual(root["issue"], {"path": [], "reason": "byte_limit"})

    def test_member_limit_counts_directories_and_nested_container_members(self):
        root_zip = make_zip([
            ("d/", b""),
            ("inner.zip", make_zip([("a.bin", b"a"), ("b.bin", b"b")])),
            ("tail.bin", b"tail"),
        ])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(b"x")], limits(max_members=4))
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        root = self.roots_by(json.loads(report_path.read_bytes()))[(A, 2)]
        # Members: 1 dir, 2 inner.zip, then inside it 3 a, 4 b; next is 5.
        self.assertEqual(root["issue"], {"path": [3], "reason": "member_limit"})
        spec3 = self.write_spec([A], [sha(b"x")], limits(max_members=3),
                                name="spec3.json")
        path3 = self.root / "r3.json"
        investigate.investigate(self.db, spec3, path3)
        root3 = self.roots_by(json.loads(path3.read_bytes()))[(A, 2)]
        # Three entries already counted before the second member of the nested
        # container is entered: dir, inner.zip, a.bin.
        self.assertEqual(root3["issue"], {"path": [2, 2],
                                          "reason": "member_limit"})

    def test_depth_limit_boundary(self):
        level4 = make_zip([("leaf.bin", b"deep")])
        level3 = make_zip([("d4.zip", level4)])
        level2 = make_zip([("d3.zip", level3)])
        root_zip = make_zip([("d2.zip", level2)])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec4 = self.write_spec([A], [sha(b"deep")], limits(max_depth=4))
        ok = self.root / "d4.json"
        investigate.investigate(self.db, spec4, ok)
        root = self.roots_by(json.loads(ok.read_bytes()))[(A, 2)]
        self.assertEqual(root["status"], "matched")
        self.assertEqual(root["leaves"][0]["path"], [1, 1, 1, 1])
        spec3 = self.write_spec([A], [sha(b"deep")], limits(max_depth=3),
                                name="d3spec.json")
        blocked = self.root / "d3.json"
        investigate.investigate(self.db, spec3, blocked)
        root3 = self.roots_by(json.loads(blocked.read_bytes()))[(A, 2)]
        self.assertEqual(root3["issue"],
                         {"path": [1, 1, 1], "reason": "depth_limit"})

    def test_nested_container_bytes_are_charged_then_its_members_again(self):
        small = b"zz"
        inner = make_zip([("small.bin", small)])
        root_zip = make_zip([("inner.zip", inner)])
        # Budget covers the nested container's own bytes but not its member too.
        budget = len(inner) + 1
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(small)],
                               limits(max_expanded_bytes=budget))
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        root = self.roots_by(json.loads(report_path.read_bytes()))[(A, 2)]
        self.assertEqual(root["issue"], {"path": [1, 1],
                                         "reason": "byte_limit"})

    def test_forged_length_and_unread_eof_become_invalid_zip(self):
        # A declared STORED member whose bytes no longer match its header:
        # the central directory stays intact but reading cannot reach a valid
        # EOF/CRC, which must be classified as invalid_zip rather than a match.
        root_zip = bytearray(make_zip([
            ("a.bin", b"ok"),
            ("b.bin", b"truncate me please", zipfile.ZIP_STORED),
        ]))
        with zipfile.ZipFile(io.BytesIO(bytes(root_zip))) as zf:
            info = zf.getinfo("b.bin")
            start = info.header_offset + 30 + len(info.filename.encode()) \
                + len(info.extra)
        # Flip a stored data byte: length is unchanged but CRC now fails.
        root_zip[start] ^= 0xFF
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", bytes(root_zip), "application/zip")])})
        spec = self.write_spec([A], [sha(b"x")])
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        root = self.roots_by(json.loads(report_path.read_bytes()))[(A, 2)]
        self.assertEqual(root["status"], "indeterminate")
        self.assertEqual(root["issue"], {"path": [2], "reason": "invalid_zip"})

    def test_high_compression_bomb_is_handled_with_bounded_memory(self):
        # Compresses to a few KiB but expands to ~8 MiB: small mail, huge tree.
        bomb_payload = b"ABCD1234" * (1 << 20)  # 8 MiB of repetitive bytes
        root_zip = make_zip([("bomb.bin", bomb_payload)])
        self.assertLess(len(root_zip), 40_000)
        # A nested variant proves the same bound holds for container spooling:
        # the inner ZIP itself is tiny while its member still expands hugely.
        nested = make_zip([("inner-bomb.bin", bomb_payload)])
        outer_zip = make_zip([("inner.zip", nested)])
        self.assertLess(len(outer_zip), 40_000)
        self.write_mail({"a.eml": make_eml(A, [
            ("bomb.zip", root_zip, "application/zip"),
            ("nested.zip", outer_zip, "application/zip"),
        ])})
        spec = self.write_spec([A], [sha(b"x")],
                               limits(max_expanded_bytes=1_000_000))
        tracemalloc.start()
        baseline = tracemalloc.take_snapshot()
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        after = tracemalloc.take_snapshot()
        stats = after.compare_to(baseline, "lineno")
        tracemalloc.stop()
        growth = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
        # The resident expansion working set stays far below the 4 MiB ceiling
        # even though each attachment decompresses ~8 MiB twice over.
        self.assertLess(growth, 4_000_000)
        report = json.loads(report_path.read_bytes())
        self.assertEqual([r["issue"]["reason"] for r in report["roots"]],
                         ["byte_limit", "byte_limit"])

    def test_budgets_are_independent_per_top_level_attachment(self):
        leaf = b"q" * 100
        root_zip = make_zip([("leaf.bin", leaf)])
        self.write_mail({"a.eml": make_eml(A, [
            ("one.zip", root_zip, "application/zip"),
            ("two.zip", root_zip, "application/zip"),
        ])})
        spec = self.write_spec([A], [sha(b"other")],
                               limits(max_expanded_bytes=100))
        report_path = self.root / "report.json"
        investigate.investigate(self.db, spec, report_path)
        report = json.loads(report_path.read_bytes())
        self.assertEqual([r["status"] for r in report["roots"]],
                         ["clear", "clear"])

    def test_no_private_temp_content_survives_a_run(self):
        root_zip = make_zip([("inner.zip", make_zip([("a.bin", b"a")])),
                             ("b.bin", b"b")])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(b"a")])
        investigate.investigate(self.db, spec, self.root / "report.json")
        leftovers = [p for p in Path(tempfile.gettempdir()).glob(".investigate-*")]
        self.assertEqual(leftovers, [])
        # Delivery staging is removed even after a successful publish.
        investigate.deliver(self.db, self.root / "report.json",
                            sha((self.root / "report.json").read_bytes()),
                            self.root / "delivery")
        self.assertEqual(
            list(Path(tempfile.gettempdir()).glob(".delivery-stage-*")), [])

    def test_duplicate_leaf_content_keeps_two_physical_identities(self):
        same = b"same bytes twice"
        root_zip = make_zip([("first.bin", same), ("second.bin", same)])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        _, report_path, report = self.investigate([A], [sha(same)])
        leaves = self.roots_by(report)[(A, 2)]["leaves"]
        self.assertEqual([(l["path"], l["matched"]) for l in leaves],
                         [([1], True), ([2], True)])
        delivery = self.root / "delivery"
        result = investigate.deliver(self.db, report_path,
                                     sha(report_path.read_bytes()), delivery)
        self.assertEqual(result["blob_count"], 1)
        self.assertEqual(result["occurrence_count"], 2)
        manifest = json.loads((delivery / "manifest.json").read_bytes())
        self.assertEqual([o["path"] for o in manifest["occurrences"]],
                         [[1], [2]])


class SpecValidationTests(InvestigateCase):
    def _raw_spec(self, value):
        path = self.root / "spec.json"
        path.write_bytes(canonical(value))
        return path

    def base_spec(self, **changes):
        value = {"messages": [A], "indicators": [sha(b"x")],
                 "limits": limits()}
        value.update(changes)
        return value

    def test_rejects_duplicate_keys_non_finite_numbers_and_unknown_fields(self):
        for raw in (b'{"messages":[],"messages":[],"indicators":[],"limits":{}}',
                    canonical(self.base_spec(limits={
                        "max_depth": 1, "max_members": 1,
                        "max_expanded_bytes": 1e99})),
                    canonical({**self.base_spec(), "extra": 1})):
            path = self.root / "bad.json"
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                investigate.investigate(self.db, path, self.root / "r.json")
            self.assertFalse((self.root / "r.json").exists())

    def test_rejects_boolean_limits_and_out_of_range_values(self):
        bad_limits = (
            {"max_depth": True, "max_members": 1, "max_expanded_bytes": 1},
            {"max_depth": 0, "max_members": 1, "max_expanded_bytes": 1},
            {"max_depth": 5, "max_members": 1, "max_expanded_bytes": 1},
            {"max_depth": 1, "max_members": 0, "max_expanded_bytes": 1},
            {"max_depth": 1, "max_members": 2001, "max_expanded_bytes": 1},
            {"max_depth": 1, "max_members": 1, "max_expanded_bytes": 0},
            {"max_depth": 1, "max_members": 1,
             "max_expanded_bytes": 1_073_741_825},
        )
        for bad in bad_limits:
            path = self._raw_spec(self.base_spec(limits=bad))
            with self.assertRaises(ValueError):
                investigate.investigate(self.db, path, self.root / "r.json")

    def test_rejects_bad_message_identities_digests_and_duplicates(self):
        cases = (
            self.base_spec(messages=[]),
            self.base_spec(messages=[A, A]),
            self.base_spec(messages=["no-brackets"]),
            self.base_spec(indicators=[]),
            self.base_spec(indicators=["ABC" + "0" * 61]),
            self.base_spec(indicators=[sha(b"x"), sha(b"x")]),
        )
        for value in cases:
            path = self._raw_spec(value)
            with self.assertRaises(ValueError):
                investigate.investigate(self.db, path, self.root / "r.json")

    def test_spec_size_limit_and_unknown_message(self):
        big = self.root / "big.json"
        big.write_bytes(b"{" + b'"a":0,' * 2_000_000 + b'"b":1}')
        with self.assertRaises(ValueError):
            investigate.investigate(self.db, big, self.root / "r.json")
        self.write_mail({"a.eml": make_eml(A, [])})
        spec = self.write_spec([X], [sha(b"x")])
        with self.assertRaisesRegex(ValueError, "not a current live message"):
            investigate.investigate(self.db, spec, self.root / "r.json")


class EvidenceIntegrityTests(InvestigateCase):
    def test_attachment_table_mismatch_fails_the_whole_command(self):
        self.write_mail({"a.eml": make_eml(
            A, [("f.bin", b"original", "application/octet-stream")])})
        con = sqlite3.connect(self.db)
        try:
            con.execute("UPDATE vault_attachments SET size_bytes=size_bytes+1 "
                        "WHERE message_id=?", (A,))
            con.commit()
        finally:
            con.close()
        spec = self.write_spec([A], [sha(b"x")])
        with self.assertRaisesRegex(ValueError, "do not match"):
            investigate.investigate(self.db, spec, self.root / "r.json")

    def test_corrupted_source_bytes_fail_integrity_not_zip_issue(self):
        self.write_mail({"a.eml": make_eml(
            A, [("f.zip", make_zip([("x", b"y")]), "application/zip")])})
        con = sqlite3.connect(self.db)
        try:
            raw = con.execute(
                "SELECT source_bytes FROM vault_messages WHERE id=?",
                (A,)).fetchone()[0]
            con.execute("UPDATE vault_messages SET source_bytes=? WHERE id=?",
                        (raw + b"\x00", A))
            con.commit()
        finally:
            con.close()
        spec = self.write_spec([A], [sha(b"x")])
        with self.assertRaisesRegex(ValueError, "SHA256"):
            investigate.investigate(self.db, spec, self.root / "r.json")

    def test_v1_missing_and_foreign_databases_are_refused_without_creation(self):
        v1 = self.root / "v1.sqlite"
        folder = self.root / "v1mail"
        folder.mkdir()
        (folder / "a.eml").write_bytes(make_eml(A, []))
        v1_build(folder, v1)
        spec = self.write_spec([A], [sha(b"x")])
        missing = self.root / "missing.sqlite"
        for db_path in (v1, missing):
            with self.assertRaises(ValueError):
                investigate.investigate(db_path, spec, self.root / "r.json")
            self.assertFalse((self.root / "r.json").exists())
        self.assertFalse(missing.exists())

    def test_more_than_200_top_level_attachments_rejected_whole(self):
        attachments = [(f"f{i:03}.bin", b"d", "application/octet-stream")
                       for i in range(201)]
        self.write_mail({"a.eml": make_eml(A, attachments)})
        spec = self.write_spec([A], [sha(b"x")])
        with self.assertRaisesRegex(ValueError, "200"):
            investigate.investigate(self.db, spec, self.root / "r.json")


class DeliveryValidationTests(InvestigateCase):
    def _approved(self, messages=(A,), indicators=None):
        hit = b"approved hit"
        indicators = indicators or [sha(hit)]
        self.write_mail({"a.eml": make_eml(
            A, [("f.zip", make_zip([("hit.bin", hit)]), "application/zip")])})
        spec = self.write_spec(messages, indicators)
        report_path = self.root / "report.json"
        result = investigate.investigate(self.db, spec, report_path)
        return report_path, result, hit

    def test_wrong_external_hash_wrong_vault_and_rewritten_report_refused(self):
        report_path, result, hit = self._approved()
        target = self.root / "delivery"
        with self.assertRaisesRegex(ValueError, "approved digest"):
            investigate.deliver(self.db, report_path, "0" * 64, target)
        self.assertFalse(target.exists())
        # Tamper with a leaf path but keep the file hash argument wrong-proof:
        document = json.loads(report_path.read_bytes())
        document["roots"][0]["leaves"][0]["path"] = [9]
        tampered = self.root / "tampered.json"
        tampered.write_bytes(canonical(document))
        with self.assertRaisesRegex(ValueError, "does not match a fresh"):
            investigate.deliver(self.db, tampered, sha(tampered.read_bytes()),
                                self.root / "d2")
        # Unknown field rejected by strict structural validation.
        document = json.loads(report_path.read_bytes())
        document["unknown"] = True
        extra = self.root / "extra.json"
        extra.write_bytes(canonical(document))
        with self.assertRaises(ValueError):
            investigate.deliver(self.db, extra, sha(extra.read_bytes()),
                                self.root / "d3")
        # Changed indicator set changes the canonical spec and must mismatch.
        document = json.loads(report_path.read_bytes())
        document["spec"]["indicators"] = [sha(b"other")]
        changed = self.root / "changed.json"
        changed.write_bytes(canonical(document))
        with self.assertRaises(ValueError):
            investigate.deliver(self.db, changed, sha(changed.read_bytes()),
                                self.root / "d4")

    def test_different_vault_identity_refused(self):
        report_path, result, hit = self._approved()
        other_folder = self.root / "other-mail"
        other_folder.mkdir()
        # Same message bytes, a separate vault file and therefore a new vault id.
        (other_folder / "a.eml").write_bytes(make_eml(
            A, [("f.zip", make_zip([("hit.bin", hit)]), "application/zip")]))
        other_db = self.root / "other.sqlite"
        vault.init(other_folder, other_db)
        with self.assertRaisesRegex(ValueError, "vault identity"):
            investigate.deliver(other_db, report_path, result["sha256"],
                                self.root / "delivery")

    def test_output_must_not_exist_including_symlink(self):
        report_path, result, _ = self._approved()
        existing = self.root / "delivery"
        existing.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            investigate.deliver(self.db, report_path, result["sha256"], existing)
        link = self.root / "link"
        os.symlink(self.root / "nowhere", link)
        with self.assertRaisesRegex(ValueError, "already exists"):
            investigate.deliver(self.db, report_path, result["sha256"], link)

    def test_report_published_only_to_new_path(self):
        report_path, result, _ = self._approved()
        duplicate = self.root / "report.json"
        with self.assertRaises(investigate.InvestigationError):
            investigate.investigate(self.db, self.root / "spec.json", duplicate)

    def test_repeated_delivery_rechecks_sources_without_using_old_copy(self):
        report_path, result, hit = self._approved()
        first = self.root / "first"
        investigate.deliver(self.db, report_path, result["sha256"], first)
        second = self.root / "second"
        again = investigate.deliver(self.db, report_path, result["sha256"],
                                    second)
        self.assertEqual(again["blob_count"], 1)
        self.assertEqual((second / "blobs" / sha(hit)).read_bytes(), hit)
        self.assertTrue(first.is_dir() and second.is_dir())


class SourceLifecycleTests(InvestigateCase):
    def test_purge_after_approval_refuses_delivery_but_unrelated_change_is_ok(self):
        hit = b"lifecycle hit"
        self.write_mail({
            "a.eml": make_eml(A, [("h.zip", make_zip([("h.bin", hit)]),
                                  "application/zip")]),
            "x.eml": make_eml(X, []),
        })
        spec = self.write_spec([A], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        # An unrelated new message and a hold do not invalidate the report.
        folder = self.root / "more"
        folder.mkdir()
        (folder / "c.eml").write_bytes(make_eml(C, []))
        vault.ingest(folder, self.db)
        vault.hold_add(self.db, "HOLD", X)
        delivery = self.root / "delivery"
        result = investigate.deliver(self.db, report_path, approved["sha256"],
                                     delivery)
        self.assertEqual(result["occurrence_count"], 1)
        # Now purge the selected message through a retention plan.
        vault.retention_plan(self.db, "PLAN", "2027-01-01T00:00:00Z")
        receipt = vault.retention_apply(self.db, "PLAN")
        self.assertIn(A, receipt["purged"])
        with self.assertRaisesRegex(ValueError, "not a current live message"):
            investigate.deliver(self.db, report_path, approved["sha256"],
                                self.root / "second")
        # The old report remains a valid historical artefact on disk and the
        # earlier delivery is untouched; a second target is refused wholesale.
        self.assertTrue(report_path.is_file())
        self.assertTrue(delivery.is_dir())
        self.assertEqual(sorted(p.name for p in delivery.iterdir()),
                         ["blobs", "manifest.json"])

    def test_recovered_vault_allows_equivalent_report_and_blocks_suppressed(self):
        hit = b"recovery hit"
        self.write_mail({
            "a.eml": make_eml(A, [("h.bin", hit, "application/octet-stream")]),
            "x.eml": make_eml(X, []),
        })
        recovery.enable(self.db)
        vault.hold_add(self.db, "KEEP", X)
        spec = self.write_spec([A, X], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        checkpoint = self.root / "checkpoint.json"
        authority = self.root / "authority.json"
        recovery.checkpoint(self.db, checkpoint)
        vault.retention_plan(self.db, "PURGE", "2027-01-01T00:00:00Z")
        vault.retention_apply(self.db, "PURGE")
        recovery.authority(self.db, authority)
        recovered = self.root / "recovered.sqlite"
        recovery.restore(checkpoint, sha(checkpoint.read_bytes()), authority,
                         sha(authority.read_bytes()), 0, recovered)
        # A is suppressed in the recovered copy: neither command can rebuild it.
        with self.assertRaisesRegex(ValueError, "not a current live message"):
            investigate.investigate(recovered, self.root / "spec.json",
                                    self.root / "r2.json")
        with self.assertRaises(ValueError):
            investigate.deliver(recovered, report_path, approved["sha256"],
                                self.root / "delivery")

    def test_unsuppressed_recovered_sources_reproduce_report_and_files(self):
        hit = b"kept hit"
        self.write_mail({"a.eml": make_eml(
            A, [("h.bin", hit, "application/octet-stream")])})
        recovery.enable(self.db)
        spec = self.write_spec([A], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        checkpoint = self.root / "checkpoint.json"
        authority = self.root / "authority.json"
        recovery.checkpoint(self.db, checkpoint)
        recovery.authority(self.db, authority)
        recovered = self.root / "recovered.sqlite"
        recovery.restore(checkpoint, sha(checkpoint.read_bytes()), authority,
                         sha(authority.read_bytes()), 0, recovered)
        second_report = self.root / "report2.json"
        again = investigate.investigate(recovered, spec, second_report)
        self.assertEqual(again["sha256"], approved["sha256"])
        self.assertEqual(second_report.read_bytes(), report_path.read_bytes())
        delivery = self.root / "delivery"
        delivered = investigate.deliver(recovered, report_path,
                                        approved["sha256"], delivery)
        self.assertEqual(delivered["blob_count"], 1)
        self.assertEqual((delivery / "blobs" / sha(hit)).read_bytes(), hit)

    def test_read_only_commands_leave_database_bytes_and_revision_untouched(self):
        hit = b"immutable hit"
        self.write_mail({"a.eml": make_eml(
            A, [("h.bin", hit, "application/octet-stream")])})
        recovery.enable(self.db)
        before_bytes = self.db.read_bytes()
        before_rev = recovery.info(self.db)["revision"]
        spec = self.write_spec([A], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        investigate.deliver(self.db, report_path, approved["sha256"],
                            self.root / "delivery")
        self.assertEqual(recovery.info(self.db)["revision"], before_rev)
        self.assertEqual(self.db.read_bytes(), before_bytes)


class FailureInjectionTests(InvestigateCase):
    def test_database_read_error_is_not_disguised_as_zip_issue(self):
        hit = b"hit before failure"
        root_zip = make_zip([("hit.bin", hit), ("next.bin", b"next")])
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", root_zip, "application/zip")])})
        spec = self.write_spec([A], [sha(hit)])
        real_connect = investigate.connect_readonly

        class FailingConnection:
            def __init__(self, real):
                self._real = real

            def execute(self, sql, *args):
                if "vault_attachments" in sql:
                    raise sqlite3.OperationalError("injected read failure")
                return self._real.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self._real, name)

        def flaky_connect(path):
            return FailingConnection(real_connect(path))

        with mock.patch.object(investigate, "connect_readonly", flaky_connect):
            with self.assertRaises(sqlite3.Error):
                investigate.investigate(self.db, spec, self.root / "r.json")
        self.assertFalse((self.root / "r.json").exists())

    def test_blob_write_error_cleans_staging_and_keeps_sources(self):
        hit = b"hit to stage"
        self.write_mail({"a.eml": make_eml(
            A, [("case.zip", make_zip([("hit.bin", hit)]), "application/zip")])})
        spec = self.write_spec([A], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        db_before = self.db.read_bytes()
        real_link = os.link

        def failing_link(src, dst, *args):
            if os.path.basename(str(dst)) == sha(hit):
                raise OSError("injected disk failure")
            return real_link(src, dst, *args)

        with mock.patch("mailroom.investigate.os.link", failing_link):
            with self.assertRaises(OSError):
                investigate.deliver(self.db, report_path, approved["sha256"],
                                    self.root / "delivery")
        self.assertFalse((self.root / "delivery").exists())
        # No private staging directory or temp leaf survives.
        leftovers = [p.name for p in self.root.iterdir()
                     if p.name.startswith((".delivery-stage-", ".leaf-",
                                           ".nested-zip-", ".investigate-"))]
        self.assertEqual(leftovers, [])
        self.assertEqual(self.db.read_bytes(), db_before)
        # A clean retry to a new target completes consistently.
        retry = investigate.deliver(self.db, report_path, approved["sha256"],
                                    self.root / "retry-delivery")
        self.assertEqual(retry["blob_count"], 1)
        self.assertEqual(
            (self.root / "retry-delivery" / "blobs" / sha(hit)).read_bytes(),
            hit)

    def test_manifest_write_failure_leaves_no_visible_directory(self):
        hit = b"manifest case"
        self.write_mail({"a.eml": make_eml(
            A, [("h.bin", hit, "application/octet-stream")])})
        spec = self.write_spec([A], [sha(hit)])
        report_path = self.root / "report.json"
        approved = investigate.investigate(self.db, spec, report_path)
        real_replace = os.replace

        def no_rename(src, dst):
            if str(dst).endswith("delivery"):
                raise OSError("injected rename failure")
            return real_replace(src, dst)

        with mock.patch("mailroom.investigate.os.rename", no_rename):
            with self.assertRaises(OSError):
                investigate.deliver(self.db, report_path, approved["sha256"],
                                    self.root / "delivery")
        self.assertFalse((self.root / "delivery").exists())
        self.assertEqual([p.name for p in self.root.iterdir()
                          if p.name.startswith(".delivery-stage-")], [])


class CliTests(InvestigateCase):
    def test_cli_success_and_failure_exit_codes_and_stdout_shapes(self):
        hit = b"cli hit"
        self.write_mail({"a.eml": make_eml(
            A, [("h.zip", make_zip([("h.bin", hit)]), "application/zip")])})
        spec = self.write_spec([A], [sha(hit)])
        report = self.root / "report.json"
        code, out, err = self.run_cli("attachment-investigate", "--db", self.db,
                                      "--spec", spec, "--output", report)
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(set(result), {"vault", "sha256", "bytes"})
        delivery = self.root / "delivery"
        code, out, err = self.run_cli(
            "attachment-deliver", "--db", self.db, "--report", report,
            "--report-sha256", result["sha256"], "--output", delivery)
        self.assertEqual(code, 0)
        delivered = json.loads(out)
        self.assertEqual(set(delivered), {"vault", "report_sha256",
                                          "blob_count", "occurrence_count"})
        # Bad hash exits 2 and prints nothing resembling success on stdout.
        code, out, err = self.run_cli(
            "attachment-deliver", "--db", self.db, "--report", report,
            "--report-sha256", "f" * 64, "--output", self.root / "other")
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("mail-archive:", err)


if __name__ == "__main__":
    unittest.main()
