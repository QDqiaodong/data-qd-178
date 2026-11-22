"""Sustainable-ingest evidence vault with legal holds and reviewed purges.

The vault is an independent database format from the v1 archive: v1 databases
are rejected without modification and vice versa. Every mutation runs in one
transaction, so a failed command leaves the last complete readable state.
"""
import json
import hashlib
import os
import re
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .archive import connect_readonly
from .parse import identifier, read_folder

FORMAT = "mailroom-vault"

SCHEMA = """
CREATE TABLE vault_meta (
 key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE vault_messages (
 id TEXT PRIMARY KEY, parent_id TEXT, thread_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('live','purged')),
 subject TEXT, sender TEXT, sent_at TEXT NOT NULL, body TEXT,
 source_sha256 TEXT NOT NULL, source_bytes BLOB
);
CREATE TABLE vault_attachments (
 message_id TEXT NOT NULL REFERENCES vault_messages(id), part INTEGER NOT NULL,
 filename TEXT, media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, sha256 TEXT NOT NULL,
 PRIMARY KEY(message_id,part)
);
CREATE VIRTUAL TABLE vault_search USING fts5(message_id UNINDEXED, subject, body, tokenize='unicode61');
CREATE TABLE vault_holds (
 hold_id TEXT PRIMARY KEY, anchor TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('active','released'))
);
CREATE TABLE vault_plans (
 plan_id TEXT PRIMARY KEY, cutoff TEXT NOT NULL, document TEXT NOT NULL
);
CREATE TABLE vault_receipts (
 plan_id TEXT PRIMARY KEY REFERENCES vault_plans(plan_id), document TEXT NOT NULL
);
CREATE INDEX vault_thread_members ON vault_messages(thread_id,sent_at,id);
"""

# Recovery tracking lives beside the business tables.  The state row is written
# by ``recovery-enable`` and is afterwards maintained by the same transaction
# helper that runs every business mutation.  It is deliberately absent from a
# vault that never enabled recovery, so all existing commands keep their exact
# observable behaviour.
RECOVERY_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_recovery_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 stream_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('source','recovered')),
 checkpoint_sha256 TEXT,
 authority_sha256 TEXT,
 authority_revision INTEGER,
 suppressed TEXT NOT NULL
);
"""

OBJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")


class HoldBlocked(Exception):
    """A saved plan cannot run because current holds cover live candidates."""

    def __init__(self, blocked):
        super().__init__("retention plan blocked by active holds")
        self.blocked = blocked


class RecoveredVault(ValueError):
    """A recovered copy is a read-only historical exhibit and refuses mutation."""

    def __init__(self):
        super().__init__("recovered vault is read-only")


def _object_id(value, label):
    if not isinstance(value, str) or not OBJECT_ID.fullmatch(value):
        raise ValueError(f"{label} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,63}}")
    return value


def parse_instant(value, label="before"):
    """ISO 8601 datetime with seconds and a Z/numeric offset, as canonical UTC."""
    if not isinstance(value, str) or not INSTANT.fullmatch(value):
        raise ValueError(f"{label} must be an ISO 8601 datetime with seconds "
                         "and a Z or +/-HH:MM timezone")
    try:
        stamp = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise ValueError(f"{label} must be an ISO 8601 datetime with seconds "
                         "and a Z or +/-HH:MM timezone") from None
    return stamp.astimezone(timezone.utc).isoformat()


def _require_vault(db, path):
    try:
        row = db.execute("SELECT value FROM vault_meta WHERE key='format'").fetchone()
    except sqlite3.Error as exc:
        raise ValueError(f"not a mailroom vault: {path}") from exc
    if row is None or row[0] != FORMAT:
        raise ValueError(f"not a mailroom vault: {path}")


def _open_vault(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"vault does not exist: {path}")
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        _require_vault(db, path)
    except BaseException:
        db.close()
        raise
    return db


def _open_vault_readonly(path):
    db = connect_readonly(path)
    try:
        _require_vault(db, path)
    except BaseException:
        db.close()
        raise
    return db


def refuse_if_recovered(path):
    """Fail fast on a recovered copy before any caller reads external inputs.

    The authoritative check still happens inside the write transaction; this
    only makes 'recovered is read-only' win over input parsing errors so a true
    replay of a former success can never be mistaken for a normal failure path
    that reads files first.  Missing or foreign databases are left to their
    ordinary error handling.
    """
    try:
        db = _open_vault_readonly(path)
    except (OSError, ValueError, sqlite3.Error):
        return
    try:
        state = _recovery_state(db)
    finally:
        db.close()
    if state is not None and state["mode"] == "recovered":
        raise RecoveredVault()


def _transact(path, operation):
    """Run operation(db) inside one immediate transaction; all or nothing.

    This is the single choke point for every business mutation (vault, review
    and collection modules all call it), so it owns two cross-cutting rules:

    * a recovered copy is read-only and refuses before the operation runs;
    * when recovery tracking is enabled, exactly one revision step is recorded
      in the same SQLite commit iff the committed business state really
      changed.  The comparison is a digest of the persisted logical business
      tables taken inside the transaction, not an in-process counter, so
      no-op replays, queries and failed work never advance the watermark.
    """
    db = _open_vault(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        state = _recovery_state(db)
        if state is not None and state["mode"] == "recovered":
            raise RecoveredVault()
        before = _business_fingerprint(db) if state is not None else None
        result = operation(db)
        after = _business_fingerprint(db) if state is not None else None
        after_state = _recovery_state(db)
        if state is not None:
            if after_state is None:
                raise ValueError("recovery state disappeared during a mutation")
            if after_state["mode"] != "source":
                raise RecoveredVault()
            if before != after:
                db.execute("UPDATE vault_recovery_state "
                           "SET revision=revision+1 WHERE singleton=1")
        elif after_state is not None:
            raise ValueError("recovery tracking changed during an untracked mutation")
        db.commit()
        return result
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def _vault_id(db):
    return db.execute("SELECT value FROM vault_meta WHERE key='vault_id'").fetchone()[0]


_RECOVERY_STATE_COLUMNS = ("stream_id", "revision", "mode", "checkpoint_sha256",
                           "authority_sha256", "authority_revision", "suppressed")


def _recovery_state(db):
    """Stored recovery row, or None when tracking was never enabled."""
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_recovery_state'"
    ).fetchone()
    if exists is None:
        return None
    row = db.execute("SELECT * FROM vault_recovery_state WHERE singleton=1").fetchone()
    if row is None:
        return None
    return {key: row[key] for key in _RECOVERY_STATE_COLUMNS}


def _business_tables(db):
    """Logical business tables; virtual/FTS shadow tables are rebuildable."""
    return [row["name"] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'vault\\_%' ESCAPE '\\' "
        "ORDER BY name")
        if row["name"] != "vault_recovery_state"
        and not row["name"].startswith("vault_search")]


def _business_fingerprint(db):
    """Digest of the complete committed logical business state.

    Row order is fixed (rowid / primary key order) and every value carries a
    type tag and length, so equal digests mean equal persisted business data.
    Only tables that exist are covered; a vault that never used review or
    collection simply contributes fewer tables.
    """
    digest = hashlib.sha256()
    for name in _business_tables(db):
        digest.update(b"T" + name.encode("utf-8") + b"\x00")
        for row in db.execute(f'SELECT * FROM "{name}" ORDER BY rowid'):
            for value in row:
                if value is None:
                    digest.update(b"N")
                elif isinstance(value, bytes):
                    digest.update(b"B" + str(len(value)).encode() + b":" + value)
                elif isinstance(value, str):
                    encoded = value.encode("utf-8")
                    digest.update(b"S" + str(len(encoded)).encode() + b":" + encoded)
                elif isinstance(value, int):
                    digest.update(b"I" + str(value).encode())
                elif isinstance(value, float):
                    digest.update(b"F" + repr(value).encode())
                else:  # defensive: sqlite3 only yields the types above
                    raise ValueError(f"unsupported stored value type in {name}")
            digest.update(b"\x01")
        digest.update(b"\x02")
    return digest.hexdigest()


def _resolve_roots(graph):
    """Thread root per identity: the parentless ancestor, else the first
    not-yet-archived parent ID. Purged identities stay in the graph."""
    roots = {}
    for key in graph:
        chain, seen, cursor = [], set(), key
        while cursor in graph and cursor not in roots:
            if cursor in seen:
                raise ValueError(f"reply cycle at {cursor}")
            seen.add(cursor)
            chain.append(cursor)
            parent = graph[cursor]
            if parent is None:
                roots[cursor] = cursor
                break
            cursor = parent
        root = roots.get(cursor, cursor)
        for node in chain:
            roots[node] = root
    return roots


def _hold_coverage(db):
    """Map message ID -> active hold IDs covering it, computed against the
    current full identity graph: the anchor itself plus every archived
    descendant that can reach the anchor along parent links (an external
    missing parent ID also matches the anchor)."""
    holds = db.execute(
        "SELECT hold_id, anchor FROM vault_holds WHERE state='active' ORDER BY hold_id"
    ).fetchall()
    coverage = {}
    if not holds:
        return coverage
    children, ids = {}, set()
    for row in db.execute("SELECT id, parent_id FROM vault_messages"):
        ids.add(row["id"])
        if row["parent_id"] is not None:
            children.setdefault(row["parent_id"], []).append(row["id"])
    for hold in holds:
        stack, seen = [hold["anchor"]], set()
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            if node in ids:
                coverage.setdefault(node, set()).add(hold["hold_id"])
            stack.extend(children.get(node, ()))
    return coverage


def _ingest_messages(db, messages):
    existing = {row["id"]: row for row in
                db.execute("SELECT id, status, source_sha256 FROM vault_messages")}
    inserted, unchanged_live, ignored_purged = [], [], []
    for key in sorted(messages):
        message = messages[key]
        row = existing.get(key)
        if row is not None:
            if row["source_sha256"] != message["sha256"]:
                raise ValueError(f"conflicting redelivery for Message-ID: {key}")
            (unchanged_live if row["status"] == "live" else ignored_purged).append(key)
            continue
        db.execute("INSERT INTO vault_messages VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (key, message["parent_id"], key, "live", message["subject"],
                    message["sender"], message["sent_at"], message["body"],
                    message["sha256"], message["raw"]))
        db.execute("INSERT INTO vault_search VALUES (?,?,?)",
                   (key, message["subject"], message["body"]))
        for part in message["attachments"]:
            db.execute("INSERT INTO vault_attachments VALUES (?,?,?,?,?,?)",
                       (key, part["part"], part["filename"], part["media_type"],
                        part["size_bytes"], part["sha256"]))
        inserted.append(key)
    # Re-resolve every thread against the whole identity graph, old and new,
    # so late parents re-root existing replies and cross-batch cycles fail.
    graph = {row["id"]: row["parent_id"]
             for row in db.execute("SELECT id, parent_id FROM vault_messages")}
    for key, root in _resolve_roots(graph).items():
        db.execute("UPDATE vault_messages SET thread_id=? WHERE id=? AND thread_id<>?",
                   (root, key, root))
    return {"inserted": sorted(inserted), "unchanged_live": sorted(unchanged_live),
            "ignored_purged": sorted(ignored_purged)}


def init(folder, target):
    """Build a new vault from one batch and publish it to a fresh path only."""
    messages = read_folder(folder)
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".vault-", dir=target.parent)
    os.close(fd)
    try:
        db = sqlite3.connect(temp)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(SCHEMA)
            vault_id = uuid.uuid4().hex
            db.execute("INSERT INTO vault_meta VALUES ('format', ?)", (FORMAT,))
            db.execute("INSERT INTO vault_meta VALUES ('schema_version', '1')")
            db.execute("INSERT INTO vault_meta VALUES ('vault_id', ?)", (vault_id,))
            result = _ingest_messages(db, messages)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        os.link(temp, target)
    finally:
        os.unlink(temp)
    return {"vault": vault_id, **result}


def ingest(folder, path):
    """Transactionally ingest the next batch into an existing vault."""
    refuse_if_recovered(path)
    messages = read_folder(folder)
    return _transact(path, lambda db: _ingest_messages(db, messages))


def hold_add(path, hold_id, anchor):
    refuse_if_recovered(path)
    _object_id(hold_id, "hold ID")
    anchor = identifier(anchor, "hold anchor")

    def operation(db):
        row = db.execute("SELECT anchor, state FROM vault_holds WHERE hold_id=?",
                         (hold_id,)).fetchone()
        if row is not None:
            if row["state"] == "released":
                raise ValueError(f"hold ID was already released: {hold_id}")
            if row["anchor"] != anchor:
                raise ValueError(f"hold ID already registered with another anchor: {hold_id}")
            return {"hold_id": hold_id, "anchor": anchor, "state": "active"}
        db.execute("INSERT INTO vault_holds VALUES (?,?,?)", (hold_id, anchor, "active"))
        return {"hold_id": hold_id, "anchor": anchor, "state": "active"}

    return _transact(path, operation)


def hold_release(path, hold_id):
    refuse_if_recovered(path)
    _object_id(hold_id, "hold ID")

    def operation(db):
        row = db.execute("SELECT anchor, state FROM vault_holds WHERE hold_id=?",
                         (hold_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown hold ID: {hold_id}")
        if row["state"] == "active":
            db.execute("UPDATE vault_holds SET state='released' WHERE hold_id=?", (hold_id,))
        return {"hold_id": hold_id, "anchor": row["anchor"], "state": "released"}

    return _transact(path, operation)


def retention_plan(path, plan_id, before):
    """Save an immutable purge plan; same ID + same instant returns the first."""
    refuse_if_recovered(path)
    _object_id(plan_id, "plan ID")
    cutoff = parse_instant(before)

    def operation(db):
        row = db.execute("SELECT cutoff, document FROM vault_plans WHERE plan_id=?",
                         (plan_id,)).fetchone()
        if row is not None:
            if row["cutoff"] != cutoff:
                raise ValueError(f"plan ID already saved with a different cutoff: {plan_id}")
            return json.loads(row["document"])
        coverage = _hold_coverage(db)
        candidates, held = [], []
        due = db.execute("SELECT id, source_sha256 FROM vault_messages "
                         "WHERE status='live' AND sent_at < ? ORDER BY id", (cutoff,))
        for message in due:
            item = {"id": message["id"], "sha256": message["source_sha256"]}
            holds = sorted(coverage.get(message["id"], ()))
            if holds:
                held.append({**item, "holds": holds})
            else:
                candidates.append(item)
        document = {"vault": _vault_id(db), "plan_id": plan_id, "before": cutoff,
                    "candidates": candidates, "held": held}
        db.execute("INSERT INTO vault_plans VALUES (?,?,?)",
                   (plan_id, cutoff, json.dumps(document, ensure_ascii=False, indent=2)))
        return document

    return _transact(path, operation)


def retention_show(path, plan_id):
    """Read-only view of the frozen plan and, if executed, the first receipt."""
    _object_id(plan_id, "plan ID")
    db = _open_vault_readonly(path)
    try:
        plan = db.execute("SELECT document FROM vault_plans WHERE plan_id=?",
                          (plan_id,)).fetchone()
        if plan is None:
            raise ValueError(f"unknown plan ID: {plan_id}")
        receipt = db.execute("SELECT document FROM vault_receipts WHERE plan_id=?",
                             (plan_id,)).fetchone()
        return {"plan": json.loads(plan["document"]),
                "receipt": json.loads(receipt["document"]) if receipt else None}
    finally:
        db.close()


def retention_apply(path, plan_id):
    """Execute the frozen plan once; replays return the first receipt as saved."""
    refuse_if_recovered(path)
    _object_id(plan_id, "plan ID")

    def operation(db):
        row = db.execute("SELECT document FROM vault_plans WHERE plan_id=?",
                         (plan_id,)).fetchone()
        if row is None:
            raise ValueError(f"unknown plan ID: {plan_id}")
        receipt = db.execute("SELECT document FROM vault_receipts WHERE plan_id=?",
                             (plan_id,)).fetchone()
        if receipt is not None:
            return json.loads(receipt["document"])
        plan = json.loads(row["document"])
        candidate_ids = [item["id"] for item in plan["candidates"]]
        status = {message["id"]: message["status"]
                  for message in db.execute("SELECT id, status FROM vault_messages")}
        coverage = _hold_coverage(db)
        blocked = [{"id": key, "holds": sorted(coverage[key])} for key in candidate_ids
                   if status[key] == "live" and key in coverage]
        if blocked:
            raise HoldBlocked(blocked)
        purged, already_purged = [], []
        for key in candidate_ids:
            if status[key] == "purged":
                already_purged.append(key)
                continue
            db.execute("UPDATE vault_messages SET status='purged', subject=NULL, "
                       "sender=NULL, body=NULL, source_bytes=NULL WHERE id=?", (key,))
            db.execute("DELETE FROM vault_attachments WHERE message_id=?", (key,))
            db.execute("DELETE FROM vault_search WHERE message_id=?", (key,))
            purged.append(key)
        document = {"vault": plan["vault"], "plan_id": plan_id,
                    "purged": sorted(purged), "already_purged": sorted(already_purged)}
        db.execute("INSERT INTO vault_receipts VALUES (?,?)",
                   (plan_id, json.dumps(document, ensure_ascii=False, indent=2)))
        return document

    return _transact(path, operation)


def vault_search(path, query):
    """Literal-AND search over live payload only; purged mail never matches."""
    if not isinstance(query, str) or len(query) > 200:
        raise ValueError("query must be at most 200 characters")
    tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    if not tokens:
        raise ValueError("query must contain a letter or digit")
    expression = " AND ".join('"' + token + '"' for token in tokens)
    db = _open_vault_readonly(path)
    try:
        return [dict(row) for row in db.execute(
            "SELECT m.id,m.thread_id,m.subject,m.sent_at FROM vault_search "
            "JOIN vault_messages m ON m.id=vault_search.message_id "
            "WHERE vault_search MATCH ? AND m.status='live' "
            "ORDER BY m.sent_at,m.id LIMIT 100", (expression,))]
    finally:
        db.close()


def vault_thread(path, message_id):
    """All current same-root nodes for a live or purged identity."""
    db = _open_vault_readonly(path)
    try:
        row = db.execute("SELECT thread_id FROM vault_messages WHERE id=?",
                         (message_id,)).fetchone()
        if row is None:
            raise ValueError("unknown message ID")
        result = []
        for item in db.execute(
                "SELECT id,parent_id,thread_id,sent_at,status,subject,sender "
                "FROM vault_messages WHERE thread_id=? ORDER BY sent_at,id",
                (row["thread_id"],)):
            node = {"id": item["id"], "parent_id": item["parent_id"],
                    "thread_id": item["thread_id"], "sent_at": item["sent_at"],
                    "status": item["status"]}
            if item["status"] == "live":
                node["subject"] = item["subject"]
                node["sender"] = item["sender"]
            result.append(node)
        return result
    finally:
        db.close()
