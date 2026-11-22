"""Resumable mboxrd mailbox intake for an existing vault.

A custodian may append a large mailbox file across several commands.  The
mboxrd subset here is explicit (no format guessing):

* the file is handled as raw bytes; lines end with LF and may keep a CR;
* a complete envelope separator is a whole line whose first five bytes are
  exactly ``From `` and which ends with LF; the sender/date text is ignored;
* except for an empty file, the first line must be such a separator;
* a record runs from one envelope line to the start of the next; the final
  record only ends at EOF once the source is sealed;
* body lines beginning with one or more ``>`` followed by ``From `` lose one
  leading ``>``; every other byte is preserved verbatim.

The ledger persists confirmed source bytes (a pinned prefix with its SHA256),
per-record results, quarantine gaps and manual dispositions.  Nothing is
committed partially: every scan or resolution is one SQLite transaction, so an
environmental failure leaves the previous complete readable state.  Source
bytes are streamed with a fixed-size working set; an oversize record is fully
crossed, never truncated into a fake valid message.
"""
import hashlib
import json
import os
import re
import stat as stat_module
from pathlib import Path

from . import io as jsonio
from .parse import parse_message
from .vault import (_ingest_messages, _object_id, _open_vault_readonly,
                    _transact, _vault_id, refuse_if_recovered)

DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_MESSAGE = 2_000_000
DEFAULT_LIMIT = 100
MAX_LIMIT = 100
CHUNK = 1 << 16  # 64 KiB: fixed upper bound on every read buffer
FROM = b"From "
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
REASONS = ("oversize", "invalid_mail", "identity_conflict", "reply_cycle")
ADMISSIONS = ("inserted", "unchanged_live", "ignored_purged")

MBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_mbox_sources (
 source_id TEXT PRIMARY KEY,
 next_offset INTEGER NOT NULL,
 pinned_bytes INTEGER NOT NULL,
 pinned_sha256 TEXT NOT NULL,
 sealed INTEGER NOT NULL CHECK(sealed IN (0,1)),
 sealed_bytes INTEGER,
 sealed_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS vault_mbox_records (
 source_id TEXT NOT NULL,
 record_number INTEGER NOT NULL,
 start_offset INTEGER NOT NULL,
 end_offset INTEGER NOT NULL,
 record_sha256 TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('admitted','unresolved','replaced','waived')),
 reason TEXT,
 initial_reason TEXT,
 message_id TEXT,
 message_sha256 TEXT,
 admission TEXT,
 replacement_sha256 TEXT,
 receipt TEXT,
 PRIMARY KEY(source_id, record_number)
);
CREATE TABLE IF NOT EXISTS vault_mbox_certificates (
 source_id TEXT PRIMARY KEY,
 document TEXT NOT NULL
);
"""


# --------------------------------------------------------------------------- io --

class MboxInputError(ValueError):
    """A structural problem with the mailbox or the decision document."""


def _digest(value, label):
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise MboxInputError(f"{label} must be 64 lowercase hexadecimal digits")
    return value


def _positive_int(value, label):
    # bool is an int subclass and must never pass as a record number or limit
    if type(value) is not int or value < 1:
        raise MboxInputError(f"{label} must be a positive integer")
    return value


def _real_file(path, label):
    target = Path(path)
    try:
        info = os.lstat(target)
    except OSError as exc:
        raise MboxInputError(f"{label} is not available: {path}") from exc
    if not stat_module.S_ISREG(info.st_mode):
        raise MboxInputError(f"{label} must be a real regular file, symlinks are refused")
    return target, info.st_size


def _ensure_mbox_tables(db):
    # Plain execute() rather than executescript so the DDL stays inside the
    # caller's all-or-nothing transaction; a first failed scan leaves no tables.
    for statement in MBOX_SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def _stream_hash(path, start, length, hasher=None):
    """Hash [start, start+length) with a fixed-size read buffer."""
    hasher = hasher or hashlib.sha256()
    remaining = length
    with open(path, "rb") as stream:
        stream.seek(start)
        while remaining:
            chunk = stream.read(min(CHUNK, remaining))
            if not chunk:
                raise MboxInputError("mailbox shrank while it was being read")
            hasher.update(chunk)
            remaining -= len(chunk)
    return hasher


def _whole_file_digest(path, size):
    return _stream_hash(path, 0, size).hexdigest()


class _LineScanner:
    """Bounded-memory view over line boundaries of one static file.

    Every internal buffer is at most one chunk; even an arbitrarily long line
    never gets materialised, because LF is a single-byte search target.
    """

    def __init__(self, path, size):
        self.path = path
        self.size = size
        self._stream = open(path, "rb")

    def close(self):
        self._stream.close()

    def read_at(self, offset, length):
        self._stream.seek(offset)
        return self._stream.read(length)

    def next_lf(self, start):
        """Absolute offset of the next LF at or after ``start``, else None."""
        self._stream.seek(start)
        base = start
        while True:
            chunk = self._stream.read(CHUNK)
            if not chunk:
                return None
            idx = chunk.find(b"\n")
            if idx >= 0:
                return base + idx
            base += len(chunk)

    def next_envelope(self, start):
        """Offset of the next complete envelope line at or after ``start``."""
        cursor = start
        while cursor < self.size:
            lf = self.next_lf(cursor)
            if lf is None:
                return None
            if self.read_at(cursor, 5) == FROM:
                return cursor
            cursor = lf + 1
        return None

    def final_line_prefix(self):
        """Up to the first five bytes of the final unterminated line.

        Returns b"" when the file is empty or ends with LF.  The pass is
        forward streaming with tiny state, so its memory use is fixed.
        """
        self._stream.seek(0)
        at_line_start = True
        prefix = b""
        while True:
            chunk = self._stream.read(CHUNK)
            if not chunk:
                break
            for byte in chunk:
                if byte == 0x0A:
                    at_line_start, prefix = True, b""
                elif at_line_start:
                    if len(prefix) < len(FROM):
                        prefix += bytes((byte,))
                    # keep collecting only while this line could still be a
                    # From envelope; once it clearly is not, drop the prefix
                    if not FROM.startswith(prefix):
                        at_line_start, prefix = False, b""
                else:
                    at_line_start = False
        return prefix


def _validate_new_head(scanner, size):
    """Head rules for a source that has never been registered.

    Empty files are legal.  Otherwise the first line must be a complete
    envelope separator; a file shorter than one line may wait as an unfinished
    tail only while its bytes can still become the ``From `` prefix.
    """
    if size == 0:
        return
    head = scanner.read_at(0, len(FROM))
    if len(head) < len(FROM):
        if not FROM.startswith(head):
            raise MboxInputError("mailbox does not start with a mboxrd From envelope")
        return  # unfinished prefix: keep waiting for the custodian's append
    if head != FROM:
        raise MboxInputError("mailbox does not start with a mboxrd From envelope")
    if scanner.next_lf(0) is None:
        # One unterminated line with the right prefix: an unfinished envelope
        # that may be completed by a later append; sealing would reject it.
        if not FROM.startswith(scanner.read_at(0, min(size, len(FROM)))):
            raise MboxInputError("mailbox does not start with a mboxrd From envelope")


# ------------------------------------------------------------- record decoding --

class _BodyReader:
    """Chunked reader bounded to ``length`` bytes; all buffers stay small."""

    def __init__(self, stream, length):
        self._stream = stream
        self._remaining = length
        self._buf = b""

    def _fill(self, need=1):
        while len(self._buf) < need and self._remaining > 0:
            chunk = self._stream.read(min(CHUNK, self._remaining))
            if not chunk:
                raise MboxInputError("mailbox shrank while it was being read")
            self._remaining -= len(chunk)
            self._buf += chunk
        return len(self._buf) >= need

    def peek(self, length):
        self._fill(length)
        return self._buf[:length]

    def take(self, length):
        data = self.peek(length)
        self._buf = self._buf[len(data):]
        return data

    def take_one(self):
        if not self._fill(1):
            return None
        byte = self._buf[:1]
        self._buf = self._buf[1:]
        return byte


def _emit(out, data, cap):
    """Append what still fits; report True once the cap is reached/passed."""
    room = cap - len(out)
    if room <= 0:
        return True
    if len(data) <= room:
        out.extend(data)
        return False
    out.extend(data[:room])
    return True


def _decode_record(path, start, envelope_end, end):
    """Raw range hash plus mboxrd-unescaped message bytes.

    Returns ``(record_sha256, decoded, oversize)``.  The envelope line is
    hashed but excluded from the decoded message.  Once the decoded bytes pass
    the single-message cap the rest is still fully read and hashed, but no
    longer accumulated, so an oversize record is crossed completely.  One
    stream covers the whole range so the envelope and body cursors never drift.
    """
    hasher = hashlib.sha256()
    out = bytearray()
    oversize = False
    with open(path, "rb") as stream:
        stream.seek(start)
        envelope_left = envelope_end - start
        while envelope_left:  # hash the envelope line, never decode it
            chunk = stream.read(min(CHUNK, envelope_left))
            if not chunk:
                raise MboxInputError("mailbox shrank while it was being read")
            hasher.update(chunk)
            envelope_left -= len(chunk)
        reader = _BodyReader(stream, end - stream.tell())
        at_line_start = True
        while True:
            byte = reader.take_one()
            if byte is None:
                break
            hasher.update(byte)
            if at_line_start and byte == b">":
                # Count the run of leading '>' on this line.  The run plus the
                # following five bytes decide whether mboxrd unescaping applies;
                # every check is bounded because the look-ahead is five.
                run = bytearray(b">")
                nxt = None
                while True:
                    nxt = reader.take_one()
                    if nxt is None:
                        break
                    hasher.update(nxt)
                    if nxt == b">":
                        run.extend(b">")
                        continue
                    break
                if nxt is not None and nxt == b"F" \
                        and reader.peek(len(FROM) - 1) == FROM[1:]:
                    # '>+From ' line: drop exactly one leading '>'.
                    rest = reader.take(len(FROM) - 1)
                    hasher.update(rest)
                    oversize = _emit(out, bytes(run[1:]), MAX_MESSAGE) or oversize
                    oversize = _emit(out, FROM, MAX_MESSAGE) or oversize
                    at_line_start = False
                    continue
                oversize = _emit(out, bytes(run), MAX_MESSAGE) or oversize
                if nxt is None:
                    break
                oversize = _emit(out, nxt, MAX_MESSAGE) or oversize
                at_line_start = (nxt == b"\n")
            else:
                oversize = _emit(out, byte, MAX_MESSAGE) or oversize
                at_line_start = (byte == b"\n")
    return hasher.hexdigest(), bytes(out), oversize


# ------------------------------------------------------------- admission core --

def _load_identity_map(db):
    return {row["id"]: {"status": row["status"], "sha256": row["source_sha256"]}
            for row in db.execute(
                "SELECT id,status,source_sha256 FROM vault_messages")}


def _load_parent_graph(db):
    return {row["id"]: row["parent_id"]
            for row in db.execute("SELECT id,parent_id FROM vault_messages")}


def _closes_cycle(graph, new_id, parent_id):
    """Would inserting new_id -> parent_id close a parent-link cycle?

    A self-referential message (parent is the new ID itself) is the shortest
    possible cycle; otherwise walk the existing graph from the parent and fail
    if the new ID is reachable from it.
    """
    if parent_id == new_id:
        return True
    seen, cursor = set(), parent_id
    while cursor is not None:
        if cursor == new_id:
            return True
        if cursor in seen:
            return True  # defensive: a valid vault never stores a cycle
        seen.add(cursor)
        cursor = graph.get(cursor)
    return False


def _admit(db, identities, graph, parsed, source_label):
    """Classify one decoded message against the whole current identity graph.

    Returns (admission, reason).  ``reason`` is None on success.  Quarantine
    writes nothing to the vault; a new identity that passes every check is
    ingested here, inside the caller's transaction.
    """
    message_id = parsed["id"]
    known = identities.get(message_id)
    if known is not None:
        if known["sha256"] != parsed["sha256"]:
            return None, "identity_conflict"
        return ("unchanged_live" if known["status"] == "live"
                else "ignored_purged"), None
    if _closes_cycle(graph, message_id, parsed["parent_id"]):
        return None, "reply_cycle"
    try:
        result = _ingest_messages(db, {message_id: parsed})
    except ValueError as exc:
        # _ingest_messages only rejects conflicting redelivery; the pre-checks
        # above make this defensive.  Re-raise environmental errors untouched.
        raise MboxInputError(str(exc)) from exc
    if result["inserted"] != [message_id]:
        raise MboxInputError(f"unexpected admission result for {source_label}")
    identities[message_id] = {"status": "live", "sha256": parsed["sha256"]}
    graph[message_id] = parsed["parent_id"]
    return "inserted", None


def _insert_ledger(db, source_id, number, start, end, record_sha, status,
                   reason=None, initial_reason=None, message_id=None,
                   message_sha=None, admission=None, replacement_sha=None,
                   receipt=None):
    db.execute(
        "INSERT INTO vault_mbox_records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (source_id, number, start, end, record_sha, status, reason,
         initial_reason, message_id, message_sha, admission,
         replacement_sha, receipt))


# -------------------------------------------------------------------- scan --

def _get_source(db, source_id):
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_mbox_sources'"
    ).fetchone()
    if exists is None:
        return None
    return db.execute(
        "SELECT * FROM vault_mbox_sources WHERE source_id=?",
        (source_id,)).fetchone()


def mbox_scan(db_path, source_id, source, limit=DEFAULT_LIMIT, seal=False):
    """Register or continue scanning one mboxrd source, optionally sealing it."""
    refuse_if_recovered(db_path)
    _object_id(source_id, "source-id")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise MboxInputError(f"limit must be an integer between 1 and {MAX_LIMIT}")
    if not isinstance(seal, bool):
        raise MboxInputError("seal must be a boolean")
    target, size = _real_file(source, "mailbox source")

    def operation(db):
        _ensure_mbox_tables(db)
        row = _get_source(db, source_id)
        scanner = _LineScanner(target, size)
        try:
            seal_bytes = seal_sha = None
            if row is None:
                _validate_new_head(scanner, size)
                db.execute(
                    "INSERT INTO vault_mbox_sources VALUES (?,?,?,?,0,NULL,NULL)",
                    (source_id, 0, 0, EMPTY_SHA256))
                next_offset = pinned = 0
                pinned_sha = EMPTY_SHA256
            else:
                next_offset, pinned, pinned_sha = (
                    row["next_offset"], row["pinned_bytes"], row["pinned_sha256"])
                if size < pinned:
                    raise MboxInputError(
                        "mailbox is shorter than the committed prefix; refusing the scan")
                verified = _stream_hash(target, 0, pinned).hexdigest()
                if verified != pinned_sha:
                    raise MboxInputError(
                        "committed mailbox prefix was rewritten; refusing the scan")
                if row["sealed"]:
                    if size != row["sealed_bytes"] \
                            or _whole_file_digest(target, size) != row["sealed_sha256"]:
                        raise MboxInputError(
                            "sealed mailbox identity changed; refusing the scan")
                elif pinned == 0 and next_offset == 0:
                    # Nothing has been committed yet: a previous command may
                    # have left only a partial From-prefix waiting.  The head
                    # rules still apply, so a divergence now fails the command.
                    _validate_new_head(scanner, size)
            if seal and (row is None or not row["sealed"]):
                # Sealing binds the complete current file, including bytes that
                # have not been scanned yet.  A dangling line that could still
                # become a From envelope is an unfinished separator and makes
                # the boundary ambiguous, so the whole seal is refused.
                seal_sha = _whole_file_digest(target, size)
                tail = scanner.final_line_prefix()
                if tail and FROM.startswith(tail):
                    raise MboxInputError(
                        "cannot seal a mailbox ending in an unfinished From line")
                seal_bytes = size
            # Incremental hasher over the bytes that will become the new pinned
            # prefix.  The committed prefix was verified byte-for-byte above;
            # feed it in once here and then extend the same hasher over only
            # the new bytes, so an arbitrarily long prefix is never re-hashed
            # per record (which would make scan cost quadratic).  On a sealed
            # source the whole file is already pinned, so hashing stops at EOF
            # and nothing beyond it is ever requested.
            prefix_hasher = hashlib.sha256()
            hash_limit = min(pinned, size)
            prefix_hasher = _stream_hash(target, 0, hash_limit, prefix_hasher)
            hashed_until = hash_limit
            identities = _load_identity_map(db)
            graph = _load_parent_graph(db)
            processed = 0
            run_pinned = pinned  # furthest offset this run's hasher reaches
            while processed < limit:
                start = next_offset
                # First complete envelope line at or after the cursor.  An
                # unterminated tail yields None and simply waits for the next
                # append; it consumes neither the limit nor a record number.
                env = scanner.next_envelope(start)
                if env is None or env != start:
                    if env is not None:
                        # Committed bytes are always envelope-aligned, so bytes
                        # before the next separator cannot be unprocessed.
                        raise MboxInputError(
                            "expected a mboxrd From envelope at the next record boundary")
                    break
                lf = scanner.next_lf(start)
                envelope_end = lf + 1
                # Search strictly after this record's own envelope line, so a
                # 'From ' inside the envelope header text cannot be mistaken
                # for the next separator.
                nxt = scanner.next_envelope(envelope_end)
                already_sealed = row is not None and row["sealed"]
                if nxt is None:
                    if already_sealed or seal:
                        end, eof_terminated = size, True
                    else:
                        break  # last record cannot be admitted before a seal
                else:
                    end, eof_terminated = nxt, False
                record_sha, decoded, oversize = _decode_record(
                    target, start, envelope_end, end)
                number = db.execute(
                    "SELECT COALESCE(MAX(record_number),0)+1 FROM vault_mbox_records "
                    "WHERE source_id=?", (source_id,)).fetchone()[0]
                status, reason, parsed = "admitted", None, None
                if oversize:
                    reason = "oversize"
                else:
                    try:
                        parsed = parse_message(decoded, f"mbox:{source_id}:{number}")
                    except ValueError:
                        reason = "invalid_mail"
                if reason is None:
                    admission, reason = _admit(
                        db, identities, graph, parsed,
                        f"mbox:{source_id}:{number}")
                if reason is not None:
                    _insert_ledger(db, source_id, number, start, end, record_sha,
                                   "unresolved", reason=reason,
                                   initial_reason=reason)
                else:
                    _insert_ledger(db, source_id, number, start, end, record_sha,
                                   "admitted", message_id=parsed["id"],
                                   message_sha=parsed["sha256"],
                                   admission=admission)
                # Feed this record's raw bytes into the running prefix hash.
                # On an unsealed source the previous iteration has reached the
                # boundary envelope (== this start); on a sealed source the
                # whole file was pre-hashed, so nothing new is added.  Every
                # source byte reaches the digest exactly once in either case.
                if hashed_until < start:
                    prefix_hasher = _stream_hash(
                        target, hashed_until, start - hashed_until,
                        prefix_hasher)
                    hashed_until = start
                if end > hashed_until:
                    prefix_hasher = _stream_hash(
                        target, hashed_until, end - hashed_until, prefix_hasher)
                    hashed_until = end
                if eof_terminated:
                    new_pinned = end
                    next_offset = end
                else:
                    # nxt is the boundary envelope start that terminates this
                    # record.  Pinning its whole line proves this record's end
                    # is committed; the next record itself still starts at nxt.
                    boundary_lf = scanner.next_lf(nxt)
                    new_pinned = boundary_lf + 1
                    if new_pinned > hashed_until:
                        prefix_hasher = _stream_hash(
                            target, hashed_until, new_pinned - hashed_until,
                            prefix_hasher)
                        hashed_until = new_pinned
                    next_offset = nxt
                run_pinned = new_pinned
                processed += 1
            if seal and row is None and size == 0:
                seal_sha, seal_bytes = EMPTY_SHA256, 0
            already_sealed = row is not None and row["sealed"]
            if seal and not already_sealed:
                # First seal: bind the complete current file, including bytes
                # no record has scanned yet.
                pinned = size
                pinned_sha = seal_sha
                db.execute(
                    "UPDATE vault_mbox_sources SET next_offset=?, pinned_bytes=?, "
                    "pinned_sha256=?, sealed=1, sealed_bytes=?, sealed_sha256=? "
                    "WHERE source_id=?",
                    (next_offset, pinned, pinned_sha, seal_bytes or size,
                     seal_sha, source_id))
            elif already_sealed:
                # The sealed identity is immutable and was verified above.
                # Whether or not the command repeated --seal, keep the
                # whole-file pin and stored digest; this run only advances
                # next_offset and the per-record ledger.
                pinned, pinned_sha = size, row["sealed_sha256"]
                db.execute(
                    "UPDATE vault_mbox_sources SET next_offset=?, pinned_bytes=?, "
                    "pinned_sha256=? WHERE source_id=?",
                    (next_offset, pinned, pinned_sha, source_id))
            else:
                pinned = run_pinned
                pinned_sha = prefix_hasher.hexdigest()
                db.execute(
                    "UPDATE vault_mbox_sources SET next_offset=?, pinned_bytes=?, "
                    "pinned_sha256=? WHERE source_id=?",
                    (next_offset, pinned, pinned_sha, source_id))
            return _show(db, source_id)
        finally:
            scanner.close()

    return _transact(db_path, operation)


# -------------------------------------------------------------------- show --

def _record_object(row):
    item = {
        "record_number": row["record_number"],
        "start": row["start_offset"],
        "end": row["end_offset"],
        "record_sha256": row["record_sha256"],
        "status": row["status"],
    }
    status = row["status"]
    if status == "unresolved":
        item["reason"] = row["reason"]
        return item
    if status in ("admitted", "replaced"):
        item["message_id"] = row["message_id"]
        item["message_sha256"] = row["message_sha256"]
        item["admission"] = row["admission"]
    if status == "replaced":
        item["reason"] = row["reason"]
        item["replacement_sha256"] = row["replacement_sha256"]
        item["initial_reason"] = row["initial_reason"]
    elif status == "waived":
        item["reason"] = row["reason"]
        item["initial_reason"] = row["initial_reason"]
    return item


def _certificate_record(row):
    item = {
        "record_number": row["record_number"],
        "start": row["start_offset"],
        "end": row["end_offset"],
        "record_sha256": row["record_sha256"],
        "status": row["status"],
    }
    if row["status"] in ("admitted", "replaced"):
        item["message_id"] = row["message_id"]
        item["message_sha256"] = row["message_sha256"]
        item["admission"] = row["admission"]
    if row["status"] == "replaced":
        item["reason"] = row["reason"]
        item["replacement_sha256"] = row["replacement_sha256"]
    elif row["status"] == "waived":
        item["reason"] = row["reason"]
    return item


def _show(db, source_id):
    row = _get_source(db, source_id)
    if row is None:
        raise MboxInputError(f"unknown mbox source-id: {source_id}")
    cert_row = db.execute(
        "SELECT document FROM vault_mbox_certificates WHERE source_id=?",
        (source_id,)).fetchone()
    records = [_record_object(item) for item in db.execute(
        "SELECT * FROM vault_mbox_records WHERE source_id=? ORDER BY record_number",
        (source_id,))]
    sealed = bool(row["sealed"])
    return {
        "vault": _vault_id(db),
        "source_id": source_id,
        "next_offset": row["next_offset"],
        "pinned_bytes": row["pinned_bytes"],
        "pinned_sha256": row["pinned_sha256"],
        "sealed": sealed,
        "source_bytes": row["sealed_bytes"] if sealed else None,
        "source_sha256": row["sealed_sha256"] if sealed else None,
        "records": records,
        "certificate": json.loads(cert_row["document"]) if cert_row else None,
    }


def mbox_show(db_path, source_id):
    """Read-only source boundary, per-record ledger and any certificate."""
    _object_id(source_id, "source-id")
    db = _open_vault_readonly(db_path)
    try:
        return _show(db, source_id)
    finally:
        db.close()


# ------------------------------------------------------------------ resolve --

def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise MboxInputError(
            f"{label} must be an object with exactly these keys: "
            + ", ".join(sorted(keys)))


def _parse_decision(path):
    decision = jsonio.load(path)
    action = decision.get("action")
    if action == "replace":
        keys = ("source_id", "record_number", "record_sha256", "action",
                "reason", "replacement")
    elif action == "waive":
        keys = ("source_id", "record_number", "record_sha256", "action",
                "reason")
    else:
        raise MboxInputError("decision.action must be 'replace' or 'waive'")
    _exact_keys(decision, keys, "DECISION")
    source_id = _object_id(decision["source_id"], "source_id")
    number = _positive_int(decision["record_number"], "record_number")
    record_sha = _digest(decision["record_sha256"], "record_sha256")
    reason = decision["reason"]
    if not isinstance(reason, str) or not reason.strip() \
            or not 1 <= len(reason) <= 2000:
        raise MboxInputError(
            "reason must be a non-blank string of at most 2000 code points")
    replacement_sha = parsed = None
    if action == "replace":
        replacement = decision["replacement"]
        if not isinstance(replacement, str) or not replacement:
            raise MboxInputError("replacement must be a nonempty .eml path")
        eml_path, eml_size = _real_file(
            Path(path).parent / replacement if not Path(replacement).is_absolute()
            else replacement, "replacement")
        if eml_path.suffix != ".eml":
            raise MboxInputError("replacement must be a .eml regular file")
        if eml_size > MAX_MESSAGE:
            raise MboxInputError("replacement message exceeds 2 MB")
        raw = eml_path.read_bytes()
        replacement_sha = hashlib.sha256(raw).hexdigest()
        parsed = parse_message(raw, f"decision:{source_id}:{number}")
    request = {"action": action, "record_sha256": record_sha, "reason": reason}
    if action == "replace":
        request["replacement_sha256"] = replacement_sha
    return source_id, number, record_sha, action, reason, replacement_sha, \
        parsed, _canonical(request)


def mbox_resolve(db_path, decision_path):
    """Replace with operator-supplied evidence, or explicitly waive one gap."""
    refuse_if_recovered(db_path)
    source_id, number, record_sha, action, reason, replacement_sha, parsed, \
        request_key = _parse_decision(decision_path)

    def operation(db):
        _ensure_mbox_tables(db)
        row = db.execute(
            "SELECT * FROM vault_mbox_records WHERE source_id=? AND record_number=?",
            (source_id, number)).fetchone()
        if row is None or _get_source(db, source_id) is None:
            raise MboxInputError(
                f"no quarantined record {number} for source {source_id}")
        if row["record_sha256"] != record_sha:
            raise MboxInputError(
                "record_sha256 does not match this quarantined record")
        if row["status"] in ("replaced", "waived"):
            if row["receipt"] != request_key:
                raise MboxInputError(
                    "this record already has a different final disposition")
            return _record_object(row)  # true replay: original receipt wins
        if row["status"] == "admitted":
            raise MboxInputError("admitted records cannot be re-decided")

        identities = _load_identity_map(db)
        graph = _load_parent_graph(db)
        if action == "waive":
            db.execute(
                "UPDATE vault_mbox_records SET status='waived', reason=?, "
                "initial_reason=?, receipt=? WHERE source_id=? AND record_number=?",
                (reason, row["reason"], request_key, source_id, number))
        else:
            admission, fail_reason = _admit(
                db, identities, graph, parsed,
                f"decision:{source_id}:{number}")
            if fail_reason is not None:
                # The gap stays unresolved: the transaction rolls back the
                # attempted ingestion, leaving no payload or half-disposition.
                raise MboxInputError(
                    f"replacement cannot pass the vault identity graph: {fail_reason}")
            db.execute(
                "UPDATE vault_mbox_records SET status='replaced', reason=?, "
                "initial_reason=?, message_id=?, message_sha256=?, admission=?, "
                "replacement_sha256=?, receipt=? "
                "WHERE source_id=? AND record_number=?",
                (reason, row["reason"], parsed["id"], parsed["sha256"],
                 admission, replacement_sha, request_key, source_id, number))
        saved = db.execute(
            "SELECT * FROM vault_mbox_records WHERE source_id=? AND record_number=?",
            (source_id, number)).fetchone()
        return _record_object(saved)

    return _transact(db_path, operation)


# ------------------------------------------------------------------ certify --

def mbox_certify(db_path, source_id):
    """Persist and return the first integrity certificate of a sealed source."""
    refuse_if_recovered(db_path)
    _object_id(source_id, "source-id")
    db = _open_vault_readonly(db_path)
    try:
        row = _get_source(db, source_id)
        if row is not None:
            cert = db.execute(
                "SELECT document FROM vault_mbox_certificates WHERE source_id=?",
                (source_id,)).fetchone()
            if cert is not None:
                return json.loads(cert["document"])  # frozen first certificate
    finally:
        db.close()

    def operation(db):
        _ensure_mbox_tables(db)
        row = _get_source(db, source_id)
        if row is None:
            raise MboxInputError(f"unknown mbox source-id: {source_id}")
        existing = db.execute(
            "SELECT document FROM vault_mbox_certificates WHERE source_id=?",
            (source_id,)).fetchone()
        if existing is not None:
            return json.loads(existing["document"])
        if not row["sealed"]:
            raise MboxInputError("cannot certify an unsealed mailbox source")
        if row["next_offset"] != row["sealed_bytes"]:
            raise MboxInputError(
                "cannot certify before every physical record has been scanned")
        unresolved = db.execute(
            "SELECT 1 FROM vault_mbox_records WHERE source_id=? AND status='unresolved'",
            (source_id,)).fetchone()
        if unresolved is not None:
            raise MboxInputError(
                "cannot certify while quarantined records remain unresolved")
        records = [_certificate_record(item) for item in db.execute(
            "SELECT * FROM vault_mbox_records WHERE source_id=? ORDER BY record_number",
            (source_id,))]
        document = {
            "vault": _vault_id(db),
            "source_id": source_id,
            "source_bytes": row["sealed_bytes"],
            "source_sha256": row["sealed_sha256"],
            "records": records,
        }
        db.execute("INSERT INTO vault_mbox_certificates VALUES (?,?)",
                   (source_id, json.dumps(document, ensure_ascii=False,
                                          allow_nan=False)))
        return document

    return _transact(db_path, operation)
