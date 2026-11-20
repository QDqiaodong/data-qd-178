"""Independent SQLite evidence archive, published only after complete validation."""
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from .parse import read_folder


SCHEMA = """
CREATE TABLE messages (
 id TEXT PRIMARY KEY, parent_id TEXT, thread_id TEXT NOT NULL, subject TEXT NOT NULL,
 sender TEXT NOT NULL, sent_at TEXT NOT NULL, body TEXT NOT NULL,
 source_sha256 TEXT NOT NULL, source_bytes BLOB NOT NULL
);
CREATE TABLE attachments (
 message_id TEXT NOT NULL REFERENCES messages(id), part INTEGER NOT NULL,
 filename TEXT, media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
 PRIMARY KEY(message_id,part)
);
CREATE VIRTUAL TABLE message_search USING fts5(message_id UNINDEXED, subject, body, tokenize='unicode61');
CREATE INDEX thread_members ON messages(thread_id,sent_at,id);
"""


def build(folder, target):
    messages = read_folder(folder)
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".archive-", dir=target.parent)
    os.close(fd)
    try:
        with sqlite3.connect(temp) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(SCHEMA)
            for key, m in sorted(messages.items()):
                db.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?,?)",
                           (key, m["parent_id"], m["thread_id"], m["subject"], m["sender"],
                            m["sent_at"], m["body"], m["sha256"], m["raw"]))
                db.execute("INSERT INTO message_search VALUES (?,?,?)", (key, m["subject"], m["body"]))
                for a in m["attachments"]:
                    db.execute("INSERT INTO attachments VALUES (?,?,?,?,?,?)",
                               (key, a["part"], a["filename"], a["media_type"], a["size_bytes"], a["sha256"]))
            db.commit()
        os.link(temp, target)
    finally:
        os.unlink(temp)
    return {"messages": len(messages), "attachments": sum(len(m["attachments"]) for m in messages.values()),
            "threads": len({m["thread_id"] for m in messages.values()})}


def connect_readonly(path):
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    return db


def search(path, query):
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("query must be at most 200 characters")
    tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    if not tokens:
        raise ValueError("query must contain a letter or digit")
    expression = " AND ".join('"' + token + '"' for token in tokens)
    with connect_readonly(path) as db:
        return [dict(row) for row in db.execute(
            "SELECT m.id,m.thread_id,m.subject,m.sent_at FROM message_search "
            "JOIN messages m ON m.id=message_search.message_id WHERE message_search MATCH ? "
            "ORDER BY m.sent_at,m.id LIMIT 100", (expression,))]


def thread(path, message_id):
    with connect_readonly(path) as db:
        row = db.execute("SELECT thread_id FROM messages WHERE id=?", (message_id,)).fetchone()
        if row is None:
            raise ValueError("unknown message ID")
        return [dict(row) for row in db.execute(
            "SELECT id,parent_id,subject,sender,sent_at FROM messages WHERE thread_id=? ORDER BY sent_at,id",
            (row["thread_id"],))]
