"""Offline external review batches for an existing vault.

A review batch registers redaction coordinates against live vault messages,
exports a self-describing redacted package for an outside reviewer, and takes
back annotations whose delivered-text coordinates are mapped precisely onto
the source body. No payload (body, subject, sender, raw message or redacted
text) is ever copied into the review tables: only coordinates, digests, public
item numbers and reviewer-submitted comments are persisted, so the existing
purge flow keeps owning source payload removal.
"""
import hashlib
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from . import io as jsonio
from .parse import identifier
from .vault import _object_id, _open_vault_readonly, _transact

FORMAT = "mailroom-review-1"
MARKER = "[REDACTED]"
MAX_PACKAGE_BYTES = 8_000_000
MAX_COMMENT_POINTS = 2_000
MAX_MESSAGES = 200
MAX_REDACTIONS = 100
MAX_ANNOTATIONS = 1_000

REVIEW_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_review_batches (
 review_id TEXT PRIMARY KEY,
 vault_id TEXT NOT NULL,
 package_sha256 TEXT NOT NULL,
 item_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_review_items (
 review_id TEXT NOT NULL,
 ord INTEGER NOT NULL,
 item_id TEXT NOT NULL,
 message_id TEXT NOT NULL,
 parent_item_id TEXT,
 source_sha256 TEXT NOT NULL,
 body_sha256 TEXT NOT NULL,
 intervals TEXT NOT NULL,
 PRIMARY KEY(review_id,item_id)
);
CREATE TABLE IF NOT EXISTS vault_review_annotations (
 review_id TEXT NOT NULL,
 annotation_id TEXT NOT NULL,
 return_id TEXT NOT NULL,
 item_id TEXT NOT NULL,
 message_id TEXT NOT NULL,
 source_sha256 TEXT NOT NULL,
 body_sha256 TEXT NOT NULL,
 delivery_start INTEGER NOT NULL,
 delivery_end INTEGER NOT NULL,
 source_start INTEGER NOT NULL,
 source_end INTEGER NOT NULL,
 comment TEXT NOT NULL,
 PRIMARY KEY(review_id,annotation_id)
);
CREATE TABLE IF NOT EXISTS vault_review_receipts (
 review_id TEXT NOT NULL,
 return_id TEXT NOT NULL,
 package_sha256 TEXT NOT NULL,
 document TEXT NOT NULL,
 feedback_canonical TEXT NOT NULL,
 PRIMARY KEY(review_id,return_id)
);
"""


def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{label} must be an object with exactly these keys: "
                         + ", ".join(sorted(keys)))


def _plain_int(value, label):
    if type(value) is not int:  # bool is a subclass of int and must be rejected
        raise ValueError(f"{label} must be an integer")
    return value


def _canonical(value):
    """The one canonical compact UTF-8 JSON encoding used for every digest."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha256_utf8(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _merge_ranges(ranges):
    """Union of (start,end) pairs already known to be integer code-point ranges."""
    ranges = sorted(ranges)
    merged = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:  # union, including adjacent intervals
            if end > merged[-1][1]:
                merged[-1][1] = end
        else:
            merged.append([start, end])
    return merged


def _merge_intervals(pairs, body_len, label):
    if not isinstance(pairs, list) or len(pairs) > MAX_REDACTIONS:
        raise ValueError(f"{label} must be a list of at most {MAX_REDACTIONS} intervals")
    ranges = []
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError(f"{label} intervals must be [start,end] pairs")
        start, end = _plain_int(pair[0], f"{label}.start"), _plain_int(pair[1], f"{label}.end")
        if not (0 <= start < end <= body_len):
            raise ValueError(f"{label} interval must satisfy 0 <= start < end <= body length")
        ranges.append((start, end))
    return _merge_ranges(ranges)


def _redact(body, intervals):
    """Return redacted text plus retained-run maps.

    Each run is (delivery_start, delivery_end, source_start, source_end) and
    describes one contiguous slice of original characters surviving in the
    delivered text. Inserted markers deliberately have no run, so marker
    characters can never be confused with a literal [REDACTED] in the body.
    """
    parts, runs = [], []
    cursor, delivery_pos = 0, 0
    for start, end in intervals:
        kept = body[cursor:start]
        if kept:
            runs.append((delivery_pos, delivery_pos + len(kept), cursor, start))
            delivery_pos += len(kept)
            parts.append(kept)
        parts.append(MARKER)
        delivery_pos += len(MARKER)
        cursor = end
    kept = body[cursor:]
    if kept:
        runs.append((delivery_pos, delivery_pos + len(kept), cursor, len(body)))
        parts.append(kept)
    return "".join(parts), runs


def _map_span(runs, text_len, start, end, label):
    """Map a delivered-text span onto source coordinates; reject marker overlap."""
    _plain_int(start, f"{label}.start")
    _plain_int(end, f"{label}.end")
    if not (0 <= start < end <= text_len):
        raise ValueError(f"{label} must satisfy 0 <= start < end <= delivered text length")
    for deliv_start, deliv_end, source_start, source_end in runs:
        if start >= deliv_start and end <= deliv_end:
            offset = start - deliv_start
            return (source_start + offset, source_start + (end - deliv_start))
    raise ValueError(f"{label} touches inserted [REDACTED] content and is not allowed")


def _package(review_id, entries):
    """Build the full package object, its digest and its on-disk byte encoding."""
    base = {"format": FORMAT, "review_id": review_id, "items": entries}
    digest = hashlib.sha256(_canonical(base)).hexdigest()
    package = {**base, "package_sha256": digest}
    return package, digest, _canonical(package)


def _ensure_review_tables(db):
    # Plain execute() calls (not executescript, which would commit the open
    # transaction) so DDL stays inside the caller's all-or-nothing transaction.
    for statement in REVIEW_SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)
    db.execute("INSERT OR IGNORE INTO vault_meta(key,value) VALUES('review_schema','1')")


def _load_item_rows(db, review_id):
    return db.execute(
        "SELECT * FROM vault_review_items WHERE review_id=? ORDER BY ord",
        (review_id,)).fetchall()


def _build_expected_entries(db, review_id):
    """Regenerate the registered package from live sources and saved coordinates.

    Fails the whole command if any source was purged or no longer hashes to the
    digests captured at registration; missing items are never silently dropped.
    """
    entries, contexts = [], {}
    for item in _load_item_rows(db, review_id):
        message = db.execute(
            "SELECT status,body,source_sha256 FROM vault_messages WHERE id=?",
            (item["message_id"],)).fetchone()
        if message is None or message["status"] != "live" or message["body"] is None:
            raise ValueError(f"source message is no longer live: {item['message_id']}")
        if message["source_sha256"] != item["source_sha256"]:
            raise ValueError(f"source digest mismatch: {item['message_id']}")
        body = message["body"]
        if _sha256_utf8(body) != item["body_sha256"]:
            raise ValueError(f"body digest mismatch: {item['message_id']}")
        intervals = json.loads(item["intervals"])
        text, runs = _redact(body, intervals)
        entry = {"item_id": item["item_id"],
                 "parent_item_id": item["parent_item_id"], "text": text}
        entries.append(dict(entry))
        contexts[item["item_id"]] = {"item": item, "text": text, "runs": runs}
    return entries, contexts


def _publish_new(target, payload):
    """Publish only to a fresh path; existing files or symlinks are refused."""
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".review-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.link(temp, target)  # atomic create; EEXIST also covers dangling symlinks
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


# ---------------------------------------------------------------- spec/open --

def _parse_spec(spec):
    _exact_keys(spec, ("review_id", "messages"), "SPEC")
    review_id = _object_id(spec["review_id"], "review_id")
    messages = spec["messages"]
    if not isinstance(messages, list) or not (1 <= len(messages) <= MAX_MESSAGES):
        raise ValueError(f"SPEC.messages must contain 1..{MAX_MESSAGES} objects")
    parsed = []
    for entry in messages:
        _exact_keys(entry, ("message_id", "redactions"), "SPEC.messages[]")
        message_id = identifier(entry["message_id"], "message_id")
        if not isinstance(entry["redactions"], list) \
                or len(entry["redactions"]) > MAX_REDACTIONS:
            raise ValueError(f"redactions must be a list of at most {MAX_REDACTIONS}")
        for pair in entry["redactions"]:  # structural checks; ranges need the body later
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError("redactions intervals must be [start,end] pairs")
            _plain_int(pair[0], "redaction.start")
            _plain_int(pair[1], "redaction.end")
        parsed.append((message_id, entry["redactions"]))
    ids = [message_id for message_id, _ in parsed]
    if len(set(ids)) != len(ids):
        raise ValueError("SPEC message_id values must not repeat")
    return review_id, parsed


def review_open(db_path, spec_path):
    spec = jsonio.load(spec_path)
    review_id, parsed = _parse_spec(spec)

    def operation(db):
        has_tables = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_review_batches'"
        ).fetchone()
        if has_tables is not None:
            batch = db.execute(
                "SELECT item_count FROM vault_review_batches WHERE review_id=?",
                (review_id,)).fetchone()
        else:
            batch = None
        if batch is not None:
            # Replay beats current liveness: a purged source must not block the
            # original registration summary from being returned.
            saved = {row["message_id"]: json.loads(row["intervals"])
                     for row in _load_item_rows(db, review_id)}
            requested_merged = {
                message_id: _merge_ranges((pair[0], pair[1]) for pair in redactions)
                for message_id, redactions in parsed}
            if set(saved) != set(requested_merged) \
                    or any(saved[message_id] != requested_merged[message_id]
                           for message_id in saved):
                raise ValueError(
                    f"review_id already registered with a different specification: {review_id}")
            return {"review_id": review_id, "item_count": batch["item_count"]}

        rows = {row["id"]: row for row in db.execute(
            "SELECT id,parent_id,status,body,source_sha256 FROM vault_messages")}
        prepared = []
        for message_id, raw_intervals in parsed:
            row = rows.get(message_id)
            if row is None or row["status"] != "live" or row["body"] is None:
                raise ValueError(f"message is not a current live message: {message_id}")
            body = row["body"]
            intervals = _merge_intervals(raw_intervals, len(body), "redactions")
            prepared.append({"message_id": message_id, "parent_id": row["parent_id"],
                             "body": body, "intervals": intervals,
                             "source_sha256": row["source_sha256"],
                             "body_sha256": _sha256_utf8(body)})
        prepared.sort(key=lambda item: item["message_id"])
        public_ids = {item["message_id"]: f"M{index:04d}"
                      for index, item in enumerate(prepared, start=1)}
        entries = []
        for ordinal, item in enumerate(prepared, start=1):
            text, _ = _redact(item["body"], item["intervals"])
            parent_item_id = public_ids.get(item["parent_id"])  # unselected parent -> None
            entries.append({"item_id": public_ids[item["message_id"]],
                            "parent_item_id": parent_item_id, "text": text})
            item["item_id"] = public_ids[item["message_id"]]
            item["parent_item_id"] = parent_item_id
            item["ordinal"] = ordinal
        package, digest, payload = _package(review_id, entries)
        if len(payload) > MAX_PACKAGE_BYTES:
            raise ValueError("complete redacted package exceeds 8,000,000 bytes")
        # All validation passed: create the review tables only now, so a failed
        # registration leaves a never-used vault byte-identical in schema too.
        _ensure_review_tables(db)
        db.execute("INSERT INTO vault_review_batches VALUES (?,?,?,?)",
                   (review_id, db.execute(
                       "SELECT value FROM vault_meta WHERE key='vault_id'").fetchone()[0],
                    digest, len(prepared)))
        for item in prepared:
            db.execute("INSERT INTO vault_review_items VALUES (?,?,?,?,?,?,?,?)",
                       (review_id, item["ordinal"], item["item_id"], item["message_id"],
                        item["parent_item_id"], item["source_sha256"], item["body_sha256"],
                        json.dumps(item["intervals"], separators=(",", ":"))))
        return {"review_id": review_id, "item_count": len(prepared)}

    return _transact(db_path, operation)


# -------------------------------------------------------------------- export --

def review_export(db_path, review_id, output_path):
    _object_id(review_id, "review_id")
    db = _open_vault_readonly(db_path)
    try:
        try:
            batch = db.execute(
                "SELECT package_sha256 FROM vault_review_batches WHERE review_id=?",
                (review_id,)).fetchone()
        except sqlite3.OperationalError as exc:  # no review tables in this vault
            raise ValueError(f"unknown review_id: {review_id}") from exc
        if batch is None:
            raise ValueError(f"unknown review_id: {review_id}")
        entries, _ = _build_expected_entries(db, review_id)
        _, digest, payload = _package(review_id, entries)
        if digest != batch["package_sha256"]:
            raise ValueError("registered package digest does not match regenerated package")
    finally:
        db.close()
    _publish_new(output_path, payload)  # filesystem publication only after full success
    return {"review_id": review_id, "item_count": len(entries),
            "package_sha256": digest, "bytes": len(payload)}


# -------------------------------------------------------------------- return --

def _validate_package_structure(package, review_id):
    _exact_keys(package, ("format", "review_id", "items", "package_sha256"), "package")
    if package["format"] != FORMAT:
        raise ValueError(f"package.format must be {FORMAT}")
    if package["review_id"] != review_id or not isinstance(package["review_id"], str):
        raise ValueError("package review_id does not match the requested batch")
    if not isinstance(package["package_sha256"], str):
        raise ValueError("package_sha256 must be a string")
    items = package["items"]
    if not isinstance(items, list) or not (1 <= len(items) <= MAX_MESSAGES):
        raise ValueError(f"package.items must contain 1..{MAX_MESSAGES} objects")
    seen = set()
    for item in items:
        _exact_keys(item, ("item_id", "parent_item_id", "text"), "package.items[]")
        if not isinstance(item["item_id"], str) or item["item_id"] in seen:
            raise ValueError("package item_id values must be unique strings")
        seen.add(item["item_id"])
        if not (item["parent_item_id"] is None
                or isinstance(item["parent_item_id"], str)):
            raise ValueError("parent_item_id must be a string or null")
        if not isinstance(item["text"], str):
            raise ValueError("item text must be a string")


def _validate_feedback_structure(feedback, review_id):
    _exact_keys(feedback, ("review_id", "package_sha256", "return_id", "annotations"),
                "feedback")
    if feedback["review_id"] != review_id or not isinstance(feedback["review_id"], str):
        raise ValueError("feedback review_id does not match the requested batch")
    if not isinstance(feedback["package_sha256"], str):
        raise ValueError("feedback package_sha256 must be a string")
    _object_id(feedback["return_id"], "return_id")
    annotations = feedback["annotations"]
    if not isinstance(annotations, list) or not (1 <= len(annotations) <= MAX_ANNOTATIONS):
        raise ValueError(f"feedback.annotations must contain 1..{MAX_ANNOTATIONS} objects")
    seen = set()
    for annotation in annotations:
        _exact_keys(annotation,
                    ("annotation_id", "item_id", "start", "end", "comment"),
                    "feedback.annotations[]")
        annotation_id = _object_id(annotation["annotation_id"], "annotation_id")
        if annotation_id in seen:
            raise ValueError(f"duplicate annotation_id in feedback: {annotation_id}")
        seen.add(annotation_id)
        if not isinstance(annotation["item_id"], str):
            raise ValueError("annotation item_id must be a string")
        _plain_int(annotation["start"], "annotation.start")
        _plain_int(annotation["end"], "annotation.end")
        comment = annotation["comment"]
        if not isinstance(comment, str) or not comment.strip() \
                or len(comment) > MAX_COMMENT_POINTS:
            raise ValueError(
                f"comment must be a non-blank string of at most {MAX_COMMENT_POINTS} code points")


def _feedback_canonical(feedback):
    ordered = dict(feedback)
    ordered["annotations"] = sorted(feedback["annotations"],
                                    key=lambda annotation: annotation["annotation_id"])
    return _canonical(ordered).decode("utf-8")


def review_return(db_path, review_id, package_path, feedback_path):
    _object_id(review_id, "review_id")
    package = jsonio.load(package_path)
    feedback = jsonio.load(feedback_path)
    _validate_package_structure(package, review_id)
    _validate_feedback_structure(feedback, review_id)
    submitted_base = {key: value for key, value in package.items()
                      if key != "package_sha256"}
    self_digest = hashlib.sha256(_canonical(submitted_base)).hexdigest()
    if self_digest != package["package_sha256"]:
        raise ValueError("package package_sha256 does not match its own content")
    if feedback["package_sha256"] != package["package_sha256"]:
        raise ValueError("feedback is not bound to the submitted package digest")

    def operation(db):
        try:
            batch = db.execute(
                "SELECT vault_id,package_sha256 FROM vault_review_batches WHERE review_id=?",
                (review_id,)).fetchone()
        except sqlite3.OperationalError as exc:
            raise ValueError(f"unknown review_id: {review_id}") from exc
        if batch is None:
            raise ValueError(f"unknown review_id: {review_id}")
        if package["package_sha256"] != batch["package_sha256"]:
            raise ValueError("package digest does not match the registered delivery")
        receipt_row = db.execute(
            "SELECT document,feedback_canonical FROM vault_review_receipts "
            "WHERE review_id=? AND return_id=?",
            (review_id, feedback["return_id"])).fetchone()
        if receipt_row is not None:
            # Replay checks stop here, before any current-liveness inspection:
            # sources purged after acceptance must not lose the first receipt.
            if _feedback_canonical(feedback) != receipt_row["feedback_canonical"]:
                raise ValueError(
                    f"return_id already accepted with different feedback: {feedback['return_id']}")
            return json.loads(receipt_row["document"])

        expected_entries, contexts = _build_expected_entries(db, review_id)
        expected_base = {"format": FORMAT, "review_id": review_id, "items": expected_entries}
        # Deep comparison defeats a tampered package whose digest was recomputed.
        # The ordered id check is needed because a reordered package keeps the
        # same content (and therefore the same digest) but breaks the contract.
        submitted_ids = [item["item_id"] for item in submitted_base["items"]]
        if submitted_ids != [entry["item_id"] for entry in expected_entries] \
                or submitted_base != expected_base:
            raise ValueError("package content does not match the registered delivery")
        annotation_rows = []
        for annotation in feedback["annotations"]:
            annotation_id = annotation["annotation_id"]
            occupied = db.execute(
                "SELECT 1 FROM vault_review_annotations WHERE review_id=? AND annotation_id=?",
                (review_id, annotation_id)).fetchone()
            if occupied is not None:
                raise ValueError(
                    f"annotation_id already used by another return in this batch: {annotation_id}")
            context = contexts.get(annotation["item_id"])
            if context is None:
                raise ValueError(f"annotation references unknown item_id: {annotation['item_id']}")
            source_start, source_end = _map_span(
                context["runs"], len(context["text"]),
                annotation["start"], annotation["end"], "annotation span")
            item = context["item"]
            annotation_rows.append((
                review_id, annotation_id, feedback["return_id"], annotation["item_id"],
                item["message_id"], item["source_sha256"], item["body_sha256"],
                annotation["start"], annotation["end"], source_start, source_end,
                annotation["comment"]))
        # All annotations and the success receipt commit together or not at all.
        for row in annotation_rows:
            db.execute("INSERT INTO vault_review_annotations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                       row)
        annotation_ids = sorted(annotation[1] for annotation in annotation_rows)
        receipt = {"review_id": review_id, "return_id": feedback["return_id"],
                   "package_sha256": package["package_sha256"],
                   "annotation_ids": annotation_ids}
        db.execute("INSERT INTO vault_review_receipts VALUES (?,?,?,?,?)",
                   (review_id, feedback["return_id"], package["package_sha256"],
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True),
                    _feedback_canonical(feedback)))
        return receipt

    return _transact(db_path, operation)


# --------------------------------------------------------------------- notes --

def review_notes(db_path, message_id):
    message_id = identifier(message_id, "message_id")
    db = _open_vault_readonly(db_path)
    try:
        identity = db.execute(
            "SELECT 1 FROM vault_messages WHERE id=?", (message_id,)).fetchone()
        if identity is None:
            raise ValueError("unknown message ID")
        has_review_tables = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_review_annotations'"
        ).fetchone()
        if has_review_tables is None:
            return {"message_id": message_id, "annotations": []}
        rows = db.execute(
            "SELECT review_id,return_id,annotation_id,item_id,source_sha256,body_sha256,"
            "delivery_start,delivery_end,source_start,source_end,comment "
            "FROM vault_review_annotations WHERE message_id=? "
            "ORDER BY review_id,return_id,annotation_id", (message_id,)).fetchall()
        annotations = [{
            "review_id": row["review_id"],
            "return_id": row["return_id"],
            "annotation_id": row["annotation_id"],
            "item_id": row["item_id"],
            "source_sha256": row["source_sha256"],
            "body_sha256": row["body_sha256"],
            "delivery_start": row["delivery_start"],
            "delivery_end": row["delivery_end"],
            "source_start": row["source_start"],
            "source_end": row["source_end"],
            "comment": row["comment"],
        } for row in rows]
        return {"message_id": message_id, "annotations": annotations}
    finally:
        db.close()
