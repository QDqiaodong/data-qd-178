"""Offline disaster-recovery checkpoints, purge authority and read-only restore.

The normal ("source") vault remains the only place where business changes may
happen.  ``recovery-enable`` gives such a vault a random persistent stream
identity and a revision watermark that starts at 0 and is advanced by exactly
one for every successful business mutation (see ``vault._transact``).  A
checkpoint is a self-contained, checksummed, canonical JSON capture of the
complete committed logical state.  ``recovery-authority`` exports the set of
purged identities of one committed state as a strict JSON document.

``recovery-restore`` verifies two offline artefacts against operator supplied
byte digests and a minimum revision, then builds a brand new database whose
only payloads are the ones the checkpoint held and the authority did not
suppress.  Everything is written to a fresh temporary database and published
by an atomic hard link; suppressed payload never reaches any disk database
built by this module, not even transiently.  The resulting copy is permanently
locked as ``recovered`` and refuses every mutation entry point.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from pathlib import Path

from .parse import identifier
from .review import REVIEW_SCHEMA
from .collection import COLLECTION_SCHEMA
from .vault import (FORMAT as VAULT_FORMAT, INSTANT, OBJECT_ID, RECOVERY_SCHEMA,
                    SCHEMA as VAULT_SCHEMA, RecoveredVault, _open_vault,
                    _open_vault_readonly, _recovery_state, _vault_id)

CHECKPOINT_FORMAT = "mailroom-recovery-checkpoint-1"
AUTHORITY_FORMAT = "mailroom-recovery-authority-1"
MAX_AUTHORITY_BYTES = 8_000_000
MAX_CHECKPOINT_BYTES = 512_000_000
DIGEST = re.compile(r"[0-9a-f]{64}")

# Fixed column order for every logical (business) table.  A checkpoint records
# these exact names, so restore never trusts schema metadata from the file.
TABLE_SPECS = (
    ("vault_meta", ("key", "value"), (), ("key",)),
    ("vault_messages",
     ("id", "parent_id", "thread_id", "status", "subject", "sender", "sent_at",
      "body", "source_sha256", "source_bytes"),
     ("source_bytes",), ("id",)),
    ("vault_attachments",
     ("message_id", "part", "filename", "media_type", "size_bytes", "sha256"),
     (), ("message_id", "part")),
    ("vault_holds", ("hold_id", "anchor", "state"), (), ("hold_id",)),
    ("vault_plans", ("plan_id", "cutoff", "document"), (), ("plan_id",)),
    ("vault_receipts", ("plan_id", "document"), (), ("plan_id",)),
    ("vault_review_batches",
     ("review_id", "vault_id", "package_sha256", "item_count"), (), ("review_id",)),
    ("vault_review_items",
     ("review_id", "ord", "item_id", "message_id", "parent_item_id",
      "source_sha256", "body_sha256", "intervals"), (), ("review_id", "ord")),
    ("vault_review_annotations",
     ("review_id", "annotation_id", "return_id", "item_id", "message_id",
      "source_sha256", "body_sha256", "delivery_start", "delivery_end",
      "source_start", "source_end", "comment"), (),
     ("review_id", "annotation_id")),
    ("vault_review_receipts",
     ("review_id", "return_id", "package_sha256", "document", "feedback_canonical"),
     (), ("review_id", "return_id")),
    ("vault_collection_intakes",
     ("intake_id", "request", "receipt"), (), ("intake_id",)),
    ("vault_collection_sources",
     ("intake_id", "package_id", "custodian", "value", "message_id",
      "source_sha256"), (), ("intake_id", "package_id", "message_id")),
)
TABLE_NAMES = tuple(spec[0] for spec in TABLE_SPECS)


# ------------------------------------------------------------------ helpers --

def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def _load_strict(path, limit, label):
    raw = Path(path).read_bytes()
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds its size limit")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} root must be an object")
    return raw, value


def _check_digest(value, label):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be 64 lowercase hexadecimal digits")
    return value


def _object_id(value, label):
    if not isinstance(value, str) or OBJECT_ID.fullmatch(value) is None:
        raise ValueError(f"{label} must match [A-Za-z0-9][A-Za-z0-9._-]{{0,63}}")
    return value


def _instant(value, label):
    if not isinstance(value, str) or INSTANT.fullmatch(value) is None:
        raise ValueError(f"{label} must be an ISO 8601 datetime with a timezone")
    return value


def _exact_identifier(value, label):
    """Message-ID must already be in canonical bracketed form (no padding)."""
    parsed = identifier(value, label)
    if parsed != value:
        raise ValueError(f"{label} is not in canonical bracketed form")
    return parsed


def _plain_int(value, label, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{label} must be an object with exactly these keys: "
                         + ", ".join(sorted(keys)))


def _publish(target, payload):
    """Publish a complete byte string to a path that must not exist yet.

    A same-directory temporary file is written and hard linked, so the final
    name appears atomically and an existing name (including a dangling symlink)
    makes the link fail without destroying anything.
    """
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".recovery-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.link(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _output(mode, vault_id, stream, revision, checkpoint_sha256=None,
            authority_sha256=None, authority_revision=None, suppressed=()):
    return {"mode": mode, "vault": vault_id, "stream": stream,
            "revision": revision, "checkpoint_sha256": checkpoint_sha256,
            "authority_sha256": authority_sha256,
            "authority_revision": authority_revision,
            "suppressed": sorted(suppressed)}


def _require_enabled(db, path):
    state = _recovery_state(db)
    if state is None:
        raise ValueError(f"recovery is not enabled for this vault: {path}")
    return state


def _read_snapshot(path, action):
    """Run action(db) against one consistent committed read snapshot."""
    db = _open_vault_readonly(path)
    try:
        db.execute("BEGIN")
        try:
            return action(db)
        finally:
            db.rollback()
    finally:
        db.close()


# --------------------------------------------------------------- enable/info --

RECOVERY_STATE_DDL = RECOVERY_SCHEMA


def enable(path):
    """Turn on recovery tracking for an existing normal vault, exactly once.

    Enabling does not change any business record and does not create a new
    vault identity.  Repeated calls return the original stream identity and
    the current watermark instead of resetting it.
    """
    db = _open_vault(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        state = _recovery_state(db)
        if state is not None:
            if state["mode"] == "recovered":
                raise RecoveredVault()
            vault_id = _vault_id(db)
            db.commit()
            return _output("source", vault_id, state["stream_id"],
                           state["revision"])
        db.execute(RECOVERY_STATE_DDL)
        stream = uuid.uuid4().hex
        db.execute("INSERT INTO vault_recovery_state VALUES (1,?,0,'source',NULL,NULL,NULL,'[]')",
                   (stream,))
        vault_id = _vault_id(db)
        db.commit()
        return _output("source", vault_id, stream, 0)
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def info(path):
    """Read-only recovery identity, watermark and persisted restore provenance."""
    db = _open_vault_readonly(path)
    try:
        state = _require_enabled(db, path)
        vault_id = _vault_id(db)
        if state["mode"] == "source":
            return _output("source", vault_id, state["stream_id"], state["revision"])
        return _output("recovered", vault_id, state["stream_id"], state["revision"],
                       state["checkpoint_sha256"], state["authority_sha256"],
                       state["authority_revision"],
                       json.loads(state["suppressed"]))
    finally:
        db.close()


# --------------------------------------------------------------- checkpoint --

def _table_snapshot(db, name, columns, blob_columns, order):
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
    if exists is None:
        return {"columns": list(columns), "blob_columns": list(blob_columns), "rows": []}
    actual = [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')]
    if set(actual) != set(columns):
        raise ValueError(f"unexpected columns in {name}")
    select = ",".join(f'"{column}"' for column in columns)
    order_sql = ",".join(f'"{column}"' for column in order)
    rows = []
    for row in db.execute(f'SELECT {select} FROM "{name}" ORDER BY {order_sql}'):
        encoded = []
        for column, value in zip(columns, row):
            if column in blob_columns:
                if value is None:
                    encoded.append(None)
                elif isinstance(value, (bytes, bytearray)):
                    encoded.append(base64.b64encode(bytes(value)).decode("ascii"))
                else:
                    raise ValueError(f"{name}.{column} is not a blob")
            else:
                if value is not None and type(value) not in (int, str):
                    raise ValueError(f"{name}.{column} has an unsupported stored type")
                encoded.append(value)
        rows.append(encoded)
    return {"columns": list(columns), "blob_columns": list(blob_columns), "rows": rows}


def _checkpoint_document(db, path):
    state = _require_enabled(db, path)
    if state["mode"] != "source":
        raise RecoveredVault()
    tables = {name: _table_snapshot(db, name, columns, blobs, order)
              for name, columns, blobs, order in TABLE_SPECS}
    meta = {row[0]: row[1] for row in tables["vault_meta"]["rows"]}
    if len(meta) != len(tables["vault_meta"]["rows"]):
        raise ValueError("duplicate vault_meta key")
    vault_id = _vault_id(db)
    if meta.get("format") != VAULT_FORMAT or meta.get("vault_id") != vault_id:
        raise ValueError("vault metadata is inconsistent")
    document = {
        "format": CHECKPOINT_FORMAT,
        "vault": vault_id,
        "stream": state["stream_id"],
        "revision": state["revision"],
        "tables": tables,
    }
    checksum = hashlib.sha256(_canonical(document)).hexdigest()
    document["checksum"] = checksum
    return document


def checkpoint(path, output):
    """Capture one self-contained checkpoint and publish it to a fresh path."""
    document = _read_snapshot(path, lambda db: _checkpoint_document(db, path))
    # Re-validate the finished artefact exactly as a reader would, so a
    # checkpoint is never published unless it is self-consistent.
    _validate_checkpoint(json.loads(_canonical(document)))
    payload = _canonical(document)
    if len(payload) > MAX_CHECKPOINT_BYTES:
        raise ValueError("checkpoint exceeds its size limit")
    digest = hashlib.sha256(payload).hexdigest()
    _publish(output, payload)
    return {"vault": document["vault"], "stream": document["stream"],
            "revision": document["revision"], "sha256": digest,
            "bytes": len(payload)}


# ---------------------------------------------------------------- authority --

def authority(path, output):
    """Export the purge authority of one committed source state."""
    def action(db):
        state = _require_enabled(db, path)
        if state["mode"] != "source":
            raise RecoveredVault()
        purged = [{"message_id": row["id"], "source_sha256": row["source_sha256"]}
                  for row in db.execute(
                      "SELECT id, source_sha256 FROM vault_messages "
                      "WHERE status='purged' ORDER BY id")]
        return state["stream_id"], _vault_id(db), state["revision"], purged

    stream, vault_id, revision, purged = _read_snapshot(path, action)
    document = {"format": AUTHORITY_FORMAT, "vault": vault_id, "stream": stream,
                "revision": revision, "purged": purged}
    _validate_authority(json.loads(_canonical(document)))
    payload = _canonical(document)
    if len(payload) > MAX_AUTHORITY_BYTES:
        raise ValueError("authority exceeds 8,000,000 bytes")
    digest = hashlib.sha256(payload).hexdigest()
    _publish(output, payload)
    return {"vault": vault_id, "stream": stream, "revision": revision,
            "sha256": digest, "purged_count": len(purged)}


# ------------------------------------------------------------------ restore --

def _checkpoint_tables(value):
    if not isinstance(value, dict) or set(value) != set(TABLE_NAMES):
        raise ValueError("checkpoint tables do not match the format")
    result = {}
    for name, columns, blob_columns, _order in TABLE_SPECS:
        table = value[name]
        _exact_keys(table, ("columns", "blob_columns", "rows"),
                    f"checkpoint.tables.{name}")
        if table["columns"] != list(columns):
            raise ValueError(f"checkpoint table {name} has unexpected columns")
        if table["blob_columns"] != list(blob_columns):
            raise ValueError(f"checkpoint table {name} has unexpected blob columns")
        if not isinstance(table["rows"], list):
            raise ValueError(f"checkpoint table {name} rows must be an array")
        rows = []
        for encoded in table["rows"]:
            if not isinstance(encoded, list) or len(encoded) != len(columns):
                raise ValueError(f"checkpoint table {name} has a malformed row")
            row = {}
            for column, item in zip(columns, encoded):
                if column in blob_columns:
                    if item is None:
                        row[column] = None
                    elif isinstance(item, str):
                        try:
                            row[column] = base64.b64decode(item.encode("ascii"),
                                                           validate=True)
                        except (binascii.Error, UnicodeEncodeError) as exc:
                            raise ValueError(
                                f"checkpoint table {name} has invalid base64") from exc
                    else:
                        raise ValueError(f"checkpoint table {name} blob must be text")
                else:
                    if item is not None and type(item) not in (int, str):
                        raise ValueError(
                            f"checkpoint table {name} has a malformed scalar")
                    row[column] = item
            rows.append(row)
        result[name] = rows
    return result


def _validate_checkpoint(document):
    _exact_keys(document, ("format", "vault", "stream", "revision", "tables",
                           "checksum"), "checkpoint")
    if document["format"] != CHECKPOINT_FORMAT:
        raise ValueError(f"checkpoint.format must be {CHECKPOINT_FORMAT}")
    for key in ("vault", "stream"):
        if not isinstance(document[key], str) or not document[key]:
            raise ValueError(f"checkpoint.{key} must be a nonempty string")
    _plain_int(document["revision"], "checkpoint.revision")
    _check_digest(document["checksum"], "checkpoint.checksum")
    base = {key: value for key, value in document.items() if key != "checksum"}
    expected = hashlib.sha256(_canonical(base)).hexdigest()
    if expected != document["checksum"]:
        raise ValueError("checkpoint content checksum does not match")

    tables = _checkpoint_tables(document["tables"])
    meta = {}
    for row in tables["vault_meta"]:
        if not isinstance(row["key"], str) or not isinstance(row["value"], str):
            raise ValueError("checkpoint vault_meta row is malformed")
        if row["key"] in meta:
            raise ValueError("checkpoint has a duplicate vault_meta key")
        meta[row["key"]] = row["value"]
    if meta.get("format") != VAULT_FORMAT:
        raise ValueError("checkpoint is not a mailroom vault")
    if meta.get("vault_id") != document["vault"]:
        raise ValueError("checkpoint vault identity is inconsistent")
    if meta.get("schema_version") != "1":
        raise ValueError("checkpoint vault schema is unsupported")

    messages = {}
    for row in tables["vault_messages"]:
        message_id = _exact_identifier(row["id"], "checkpoint message id")
        if message_id in messages:
            raise ValueError(f"checkpoint has a duplicate message identity: {message_id}")
        if row["parent_id"] is not None:
            _exact_identifier(row["parent_id"], "checkpoint parent id")
        _exact_identifier(row["thread_id"], "checkpoint thread id")
        if row["status"] not in ("live", "purged"):
            raise ValueError("checkpoint message has an invalid status")
        _check_digest(row["source_sha256"], "checkpoint source_sha256")
        _instant(row["sent_at"], "checkpoint message sent_at")
        if row["status"] == "purged":
            if any(row[key] is not None
                   for key in ("subject", "sender", "body", "source_bytes")):
                raise ValueError("checkpoint purged message retains payload")
        else:
            if not isinstance(row["subject"], str) or not isinstance(row["sender"], str) \
                    or not isinstance(row["body"], str):
                raise ValueError("checkpoint live message lacks text payload")
            if not isinstance(row["source_bytes"], (bytes, bytearray)):
                raise ValueError("checkpoint live message lacks raw payload")
        messages[message_id] = row

    attachments = set()
    for row in tables["vault_attachments"]:
        message_id = _exact_identifier(row["message_id"], "attachment message id")
        message = messages.get(message_id)
        if message is None or message["status"] != "live":
            raise ValueError("checkpoint attachment references a non-live message")
        _plain_int(row["part"], "attachment.part")
        if row["filename"] is not None and not isinstance(row["filename"], str):
            raise ValueError("attachment filename must be a string or null")
        if not isinstance(row["media_type"], str) or not row["media_type"]:
            raise ValueError("attachment media type is malformed")
        _plain_int(row["size_bytes"], "attachment.size_bytes")
        _check_digest(row["sha256"], "attachment.sha256")
        key = (message_id, row["part"])
        if key in attachments:
            raise ValueError("checkpoint has a duplicate attachment part")
        attachments.add(key)

    holds = set()
    for row in tables["vault_holds"]:
        _object_id(row["hold_id"], "hold id")
        _exact_identifier(row["anchor"], "hold anchor")
        if row["state"] not in ("active", "released"):
            raise ValueError("hold state is malformed")
        if row["hold_id"] in holds:
            raise ValueError("checkpoint has a duplicate hold id")
        holds.add(row["hold_id"])

    plans = set()
    for row in tables["vault_plans"]:
        _object_id(row["plan_id"], "plan id")
        _instant(row["cutoff"], "plan cutoff")
        if not isinstance(row["document"], str):
            raise ValueError("plan document must be a string")
        if row["plan_id"] in plans:
            raise ValueError("checkpoint has a duplicate plan id")
        plans.add(row["plan_id"])
    receipts = set()
    for row in tables["vault_receipts"]:
        if not isinstance(row["plan_id"], str) or not isinstance(row["document"], str):
            raise ValueError("receipt row is malformed")
        if row["plan_id"] not in plans:
            raise ValueError("receipt references an unknown plan")
        if row["plan_id"] in receipts:
            raise ValueError("checkpoint has a duplicate receipt")
        receipts.add(row["plan_id"])

    batches = set()
    for row in tables["vault_review_batches"]:
        _object_id(row["review_id"], "review id")
        if not isinstance(row["vault_id"], str) or not isinstance(row["package_sha256"], str):
            raise ValueError("review batch row is malformed")
        _plain_int(row["item_count"], "review item_count")
        if row["review_id"] in batches:
            raise ValueError("checkpoint has a duplicate review batch")
        batches.add(row["review_id"])
    items = set()
    for row in tables["vault_review_items"]:
        if row["review_id"] not in batches:
            raise ValueError("review item references an unknown batch")
        _plain_int(row["ord"], "review item ord")
        key = (row["review_id"], row["ord"])
        if key in items:
            raise ValueError("checkpoint has a duplicate review item")
        items.add(key)
        if not isinstance(row["item_id"], str) or not isinstance(row["intervals"], str):
            raise ValueError("review item row is malformed")
        _exact_identifier(row["message_id"], "review item message id")
        if row["parent_item_id"] is not None and not isinstance(row["parent_item_id"], str):
            raise ValueError("review parent item id is malformed")
        _check_digest(row["source_sha256"], "review item source_sha256")
        _check_digest(row["body_sha256"], "review item body_sha256")
    annotation_ids = set()
    for row in tables["vault_review_annotations"]:
        if row["review_id"] not in batches:
            raise ValueError("review annotation references an unknown batch")
        _object_id(row["annotation_id"], "annotation id")
        key = (row["review_id"], row["annotation_id"])
        if key in annotation_ids:
            raise ValueError("checkpoint has a duplicate review annotation")
        annotation_ids.add(key)
        _exact_identifier(row["message_id"], "annotation message id")
        if not isinstance(row["comment"], str):
            raise ValueError("annotation comment must be a string")
        for column in ("delivery_start", "delivery_end", "source_start", "source_end"):
            _plain_int(row[column], f"annotation.{column}")
        for column in ("source_sha256", "body_sha256"):
            _check_digest(row[column], f"annotation.{column}")
    for row in tables["vault_review_receipts"]:
        if row["review_id"] not in batches:
            raise ValueError("review receipt references an unknown batch")
        _object_id(row["return_id"], "review return id")

    intakes = set()
    for row in tables["vault_collection_intakes"]:
        _object_id(row["intake_id"], "intake id")
        if not isinstance(row["request"], str) or not isinstance(row["receipt"], str):
            raise ValueError("collection intake row is malformed")
        if row["intake_id"] in intakes:
            raise ValueError("checkpoint has a duplicate collection intake")
        intakes.add(row["intake_id"])
    sources = set()
    for row in tables["vault_collection_sources"]:
        if row["intake_id"] not in intakes:
            raise ValueError("collection source references an unknown intake")
        key = (row["intake_id"], row["package_id"], row["message_id"])
        if key in sources:
            raise ValueError("checkpoint has a duplicate collection source")
        sources.add(key)
        _object_id(row["package_id"], "package id")
        _object_id(row["custodian"], "custodian")
        _plain_int(row["value"], "collection source value")
        _exact_identifier(row["message_id"], "collection source message id")
        _check_digest(row["source_sha256"], "collection source sha256")
    return document, tables, messages


def _validate_authority(document):
    _exact_keys(document, ("format", "vault", "stream", "revision", "purged"),
                "authority")
    if document["format"] != AUTHORITY_FORMAT:
        raise ValueError(f"authority.format must be {AUTHORITY_FORMAT}")
    for key in ("vault", "stream"):
        if not isinstance(document[key], str) or not document[key]:
            raise ValueError(f"authority.{key} must be a nonempty string")
    _plain_int(document["revision"], "authority.revision")
    purged = document["purged"]
    if not isinstance(purged, list):
        raise ValueError("authority.purged must be an array")
    result, previous = {}, None
    for entry in purged:
        _exact_keys(entry, ("message_id", "source_sha256"), "authority.purged[]")
        message_id = _exact_identifier(entry["message_id"], "authority message id")
        _check_digest(entry["source_sha256"], "authority source_sha256")
        if previous is not None and message_id <= previous:
            raise ValueError("authority purged identities must be unique and sorted")
        previous = message_id
        result[message_id] = entry["source_sha256"]
    return document, result


def _apply_authority(checkpoint_doc, checkpoint_messages, authority_doc,
                     authority_map, minimum):
    if authority_doc["vault"] != checkpoint_doc["vault"]:
        raise ValueError("authority and checkpoint belong to different vaults")
    if authority_doc["stream"] != checkpoint_doc["stream"]:
        raise ValueError("authority and checkpoint belong to different streams")
    if authority_doc["revision"] < checkpoint_doc["revision"]:
        raise ValueError("authority revision is older than the checkpoint")
    if authority_doc["revision"] < minimum:
        raise ValueError("authority revision is below the required minimum")

    checkpoint_purged = {message_id: row["source_sha256"]
                         for message_id, row in checkpoint_messages.items()
                         if row["status"] == "purged"}
    for message_id, sha256 in checkpoint_purged.items():
        if message_id not in authority_map:
            raise ValueError(
                f"authority omits an identity already purged in the checkpoint: {message_id}")
        if authority_map[message_id] != sha256:
            raise ValueError(f"authority source digest conflict for {message_id}")
    if authority_doc["revision"] == checkpoint_doc["revision"]:
        if set(authority_map) != set(checkpoint_purged):
            raise ValueError("authority at the checkpoint revision claims a different "
                             "purged set")
    suppressed = []
    for message_id, sha256 in authority_map.items():
        row = checkpoint_messages.get(message_id)
        if row is None:
            continue  # genuinely later identity: checked structurally, never injected
        if row["source_sha256"] != sha256:
            raise ValueError(f"authority source digest conflict for {message_id}")
        if row["status"] == "live":
            suppressed.append(message_id)
    return sorted(suppressed)


def _insert_rows(db, name, columns, rows):
    placeholders = ",".join("?" for _ in columns)
    names = ",".join(f'"{column}"' for column in columns)
    db.executemany(f'INSERT INTO "{name}" ({names}) VALUES ({placeholders})',
                   [tuple(row[column] for column in columns) for row in rows])


def _build_database(temp, tables, checkpoint_revision, suppressed, stream,
                    checkpoint_digest, authority_digest, authority_revision):
    suppressed_set = set(suppressed)
    db = sqlite3.connect(temp)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys=ON")
        db.executescript(VAULT_SCHEMA)
        db.executescript(REVIEW_SCHEMA)
        db.executescript(COLLECTION_SCHEMA)
        db.execute(RECOVERY_STATE_DDL)

        _insert_rows(db, "vault_meta", ("key", "value"), tables["vault_meta"])

        filtered_messages = []
        live_payloads = []
        for row in tables["vault_messages"]:
            item = dict(row)
            if item["id"] in suppressed_set:
                # Never write the old payload: it is dropped before the insert.
                item.update(status="purged", subject=None, sender=None,
                            body=None, source_bytes=None)
            filtered_messages.append(item)
            if item["status"] == "live":
                live_payloads.append(item)
        _insert_rows(db, "vault_messages",
                     ("id", "parent_id", "thread_id", "status", "subject", "sender",
                      "sent_at", "body", "source_sha256", "source_bytes"),
                     filtered_messages)

        attachments = [row for row in tables["vault_attachments"]
                       if row["message_id"] not in suppressed_set]
        _insert_rows(db, "vault_attachments",
                     ("message_id", "part", "filename", "media_type", "size_bytes",
                      "sha256"), attachments)

        for name, columns, _blobs, _order in TABLE_SPECS:
            if name in ("vault_meta", "vault_messages", "vault_attachments"):
                continue
            _insert_rows(db, name, columns, tables[name])

        for row in live_payloads:
            db.execute("INSERT INTO vault_search VALUES (?,?,?)",
                       (row["id"], row["subject"], row["body"]))

        encoded_suppressed = json.dumps(sorted(suppressed), separators=(",", ":"))
        db.execute("INSERT INTO vault_recovery_state VALUES "
                   "(1,?,?,'recovered',?,?,?,?)",
                   (stream, checkpoint_revision, checkpoint_digest,
                    authority_digest, authority_revision, encoded_suppressed))
        db.commit()
        _verify_built(db, tables, filtered_messages, suppressed,
                      checkpoint_revision, stream, checkpoint_digest, authority_digest,
                      authority_revision)
    except BaseException:
        db.rollback()
        db.close()
        raise
    else:
        db.close()


def _verify_built(db, tables, filtered_messages, suppressed, checkpoint_revision,
                  stream, checkpoint_digest, authority_digest, authority_revision):
    """Re-read the finished database and confirm data, indexes and lock."""
    stored = {row["id"]: dict(row) for row in
              db.execute("SELECT * FROM vault_messages")}
    if set(stored) != {row["id"] for row in filtered_messages}:
        raise ValueError("restored message identities do not match the checkpoint")
    for row in filtered_messages:
        actual = stored[row["id"]]
        for column in ("parent_id", "thread_id", "status", "subject", "sender",
                       "sent_at", "source_sha256", "source_bytes"):
            if actual[column] != row[column]:
                raise ValueError(f"restored message {row['id']} differs from the checkpoint")
    expected_meta = sorted((row["key"], row["value"]) for row in tables["vault_meta"])
    actual_meta = sorted(tuple(row) for row in
                         db.execute("SELECT key,value FROM vault_meta"))
    if actual_meta != expected_meta:
        raise ValueError("restored vault metadata differs from the checkpoint")
    expected_attachments = sorted(
        tuple(row[column] for column in
              ("message_id", "part", "filename", "media_type", "size_bytes", "sha256"))
        for row in tables["vault_attachments"]
        if row["message_id"] not in set(suppressed))
    actual_attachments = sorted(tuple(row) for row in db.execute(
        "SELECT message_id,part,filename,media_type,size_bytes,sha256 "
        "FROM vault_attachments"))
    if actual_attachments != expected_attachments:
        raise ValueError("restored attachments differ from the retained payload")
    for name, columns, _blobs, _order in TABLE_SPECS:
        if name in ("vault_meta", "vault_messages", "vault_attachments"):
            continue
        expected = [tuple(row[column] for column in columns) for row in tables[name]]
        actual = [tuple(row) for row in
                  db.execute('SELECT ' + ",".join(f'"{c}"' for c in columns)
                             + f' FROM "{name}"')]
        if sorted(map(repr, actual)) != sorted(map(repr, expected)):
            raise ValueError(f"restored table {name} differs from the checkpoint")
    expected_search = sorted((row["id"], row["subject"], row["body"])
                             for row in filtered_messages if row["status"] == "live")
    actual_search = sorted(tuple(row) for row in
                           db.execute("SELECT message_id,subject,body FROM vault_search"))
    if actual_search != expected_search:
        raise ValueError("restored search index differs from the retained payload")
    state = _recovery_state(db)
    if state is None or state["mode"] != "recovered":
        raise ValueError("restored copy is not locked as recovered")
    if state["stream_id"] != stream:
        raise ValueError("restored stream identity is inconsistent")
    if state["revision"] != checkpoint_revision:
        raise ValueError("restored revision does not match the checkpoint")
    if state["checkpoint_sha256"] != checkpoint_digest:
        raise ValueError("restored checkpoint digest is inconsistent")
    if state["authority_sha256"] != authority_digest:
        raise ValueError("restored authority digest is inconsistent")
    if state["authority_revision"] != authority_revision:
        raise ValueError("restored authority revision is inconsistent")
    if json.loads(state["suppressed"]) != sorted(suppressed):
        raise ValueError("restored suppressed list is inconsistent")


def parse_revision(text):
    """Operator supplied minimum revision: a decimal non-negative integer."""
    if not isinstance(text, str) or re.fullmatch(r"[0-9]+", text) is None:
        raise ValueError("minimum revision must be a non-negative decimal integer")
    return int(text)


def restore(checkpoint_path, checkpoint_sha256, authority_path, authority_sha256,
            minimum_revision, target):
    """Verify offline materials and build a locked recovered copy."""
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"output already exists: {target}")
    _check_digest(checkpoint_sha256, "checkpoint sha256")
    _check_digest(authority_sha256, "authority sha256")
    _plain_int(minimum_revision, "minimum revision")

    checkpoint_raw, checkpoint_doc = _load_strict(
        checkpoint_path, MAX_CHECKPOINT_BYTES, "checkpoint")
    if hashlib.sha256(checkpoint_raw).hexdigest() != checkpoint_sha256:
        raise ValueError("checkpoint file digest does not match the trusted digest")
    authority_raw, authority_doc = _load_strict(
        authority_path, MAX_AUTHORITY_BYTES, "authority")
    if hashlib.sha256(authority_raw).hexdigest() != authority_sha256:
        raise ValueError("authority file digest does not match the trusted digest")

    checkpoint_doc, tables, messages = _validate_checkpoint(checkpoint_doc)
    authority_doc, authority_map = _validate_authority(authority_doc)
    suppressed = _apply_authority(checkpoint_doc, messages, authority_doc,
                                  authority_map, minimum_revision)

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".recovery-vault-", dir=target.parent)
    os.close(fd)
    try:
        _build_database(temp, tables, checkpoint_doc["revision"], suppressed,
                        checkpoint_doc["stream"], checkpoint_sha256,
                        authority_sha256, authority_doc["revision"])
        os.link(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return _output("recovered", checkpoint_doc["vault"], checkpoint_doc["stream"],
                   checkpoint_doc["revision"], checkpoint_sha256,
                   authority_sha256, authority_doc["revision"], suppressed)
