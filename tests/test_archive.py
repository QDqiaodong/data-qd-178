import hashlib
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from mailroom.archive import build, search, thread
from mailroom.parse import read_folder


class MailTests(unittest.TestCase):
    def test_real_archive_search_thread_and_attachment_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "mail.sqlite"
            self.assertEqual(build("fixtures/mail", db), {"messages": 2, "attachments": 1, "threads": 1})
            self.assertEqual([r["id"] for r in search(db, "harbor")],
                             ["<planning@example.invalid>", "<reply@example.invalid>"])
            self.assertEqual(len(thread(db, "<reply@example.invalid>")), 2)
            with sqlite3.connect(db) as con:
                size, sha = con.execute("SELECT size_bytes,sha256 FROM attachments").fetchone()
                raw, source_sha = con.execute("SELECT source_bytes,source_sha256 FROM messages ORDER BY id LIMIT 1").fetchone()
            self.assertEqual(size, 7)
            self.assertEqual(sha, hashlib.sha256(b"agenda\n").hexdigest())
            self.assertEqual(source_sha, hashlib.sha256(raw).hexdigest())
            self.assertEqual(search(db, "agenda"), [])  # attachment text is not body text

    def test_archive_query_survives_source_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "mail"
            shutil.copytree("fixtures/mail", folder)
            db = Path(tmp) / "a.sqlite"
            build(folder, db)
            shutil.rmtree(folder)
            self.assertEqual(len(search(db, "restoration")), 2)

    def test_duplicate_id_and_reply_cycle_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "mail"
            shutil.copytree("fixtures/mail", folder)
            shutil.copy(folder / "001.eml", folder / "003.eml")
            with self.assertRaisesRegex(ValueError, "duplicate Message-ID"):
                read_folder(folder)
            (folder / "003.eml").unlink()
            p = folder / "001.eml"
            p.write_text(p.read_text().replace("Subject:", "In-Reply-To: <reply@example.invalid>\nSubject:", 1))
            with self.assertRaisesRegex(ValueError, "reply cycle"):
                read_folder(folder)

    def test_existing_target_preserved_and_temp_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "existing.sqlite"
            target.write_bytes(b"KEEP")
            with self.assertRaises(FileExistsError):
                build("fixtures/mail", target)
            self.assertEqual(target.read_bytes(), b"KEEP")
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ["existing.sqlite"])

    def test_missing_parent_is_explicit_external_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy("fixtures/mail/002.eml", Path(tmp) / "002.eml")
            row = next(iter(read_folder(tmp).values()))
            self.assertEqual(row["thread_id"], "<planning@example.invalid>")
            self.assertEqual(row["parent_id"], "<planning@example.invalid>")

    def test_readonly_query_does_not_create_absent_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "missing.sqlite"
            with self.assertRaises(sqlite3.OperationalError):
                search(target, "harbor")
            self.assertFalse(target.exists())
