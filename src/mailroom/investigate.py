"""Offline attachment indicator investigation and forensic delivery.

Two read-only commands run on an existing mailroom vault and never touch the
historical source folders, mbox files or checkpoints:

* ``attachment-investigate`` re-parses each selected message from its archived
  ``source_bytes``, proves the stored attachment summaries against the actual
  MIME payload, then walks every top-level attachment.  ZIP containers are
  opened with the standard library only; each container gets its own fixed
  depth / member / expanded-byte budget.  A budget, encryption, compression or
  corruption problem stops that one attachment and is reported honestly as an
  indeterminate root instead of being disguised as "not found".
* ``attachment-deliver`` verifies the operator-approved report bytes against
  the supplied SHA256, re-runs the whole investigation from the current live
  sources inside one read-only snapshot and compares the complete expected
  report.  Only when every root is complete does it publish the matched leaf
  blobs (one physical blob per digest, every physical occurrence recorded).

Expanded content never accumulates in memory: leaves are hashed in fixed-size
chunks and nested ZIPs are streamed to a private temporary file that is removed
as soon as its subtree has been walked.  Nothing here writes to the vault.
"""
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
import zlib
from email import policy
from email.parser import BytesParser
from pathlib import Path

from . import io as jsonio
from .archive import connect_readonly
from .parse import identifier
from .vault import FORMAT as VAULT_FORMAT, _vault_id

REPORT_FORMAT = "mailroom-attachment-report-1"
DELIVERY_FORMAT = "mailroom-attachment-delivery-1"
MAX_SPEC_BYTES = 8_000_000
MAX_REPORT_BYTES = 8_000_000
MAX_MESSAGES = 100
MAX_INDICATORS = 128
MAX_TOP_ATTACHMENTS = 200
DIGEST = re.compile(r"[0-9a-f]{64}")
LIMIT_RANGES = {"max_depth": (1, 4), "max_members": (1, 2000),
                "max_expanded_bytes": (1, 1_073_741_824)}
# One fixed read window; the resident expanded-content working set never grows
# with the configured expanded-byte budget or the real expansion size.
CHUNK = 1 << 18  # 256 KiB
# Failures raised by zipfile/zlib while reading container members.
_ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError)
SUPPORTED_METHODS = frozenset((zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))

ISSUE_REASONS = ("depth_limit", "member_limit", "byte_limit", "encrypted",
                 "unsupported_compression", "invalid_zip")


class InvestigationError(ValueError):
    """A structural, evidence-integrity or environmental command failure.

    Ordinary ZIP check problems are never raised: they become indeterminate
    roots in a successful report.
    """


class _Issue(Exception):
    """The first check problem found inside one top-level attachment."""

    def __init__(self, path, reason):
        super().__init__(reason)
        self.path = list(path)
        self.reason = reason


# ----------------------------------------------------------------- spec/JSON --

def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise InvestigationError(
            f"{label} must be an object with exactly these keys: "
            + ", ".join(sorted(keys)))


def _plain_int(value, label):
    if type(value) is not int:  # bool is an int subclass and must be rejected
        raise InvestigationError(f"{label} must be a non-boolean integer")
    return value


def parse_spec(spec):
    """Validate the strict SPEC object and return its normalized identity."""
    _exact_keys(spec, ("messages", "indicators", "limits"), "SPEC")
    messages = spec["messages"]
    if not isinstance(messages, list) or not (1 <= len(messages) <= MAX_MESSAGES):
        raise InvestigationError(f"SPEC.messages must contain 1..{MAX_MESSAGES} entries")
    normalized_messages = []
    for entry in messages:
        normalized_messages.append(identifier(entry, "SPEC message_id"))
    if len(set(normalized_messages)) != len(normalized_messages):
        raise InvestigationError("SPEC message_id values must not repeat")
    indicators = spec["indicators"]
    if not isinstance(indicators, list) \
            or not (1 <= len(indicators) <= MAX_INDICATORS):
        raise InvestigationError(
            f"SPEC.indicators must contain 1..{MAX_INDICATORS} digests")
    normalized_indicators = []
    for entry in indicators:
        if not isinstance(entry, str) or DIGEST.fullmatch(entry) is None:
            raise InvestigationError(
                "SPEC indicators must be 64 lowercase hexadecimal SHA256 values")
        normalized_indicators.append(entry)
    if len(set(normalized_indicators)) != len(normalized_indicators):
        raise InvestigationError("SPEC indicator values must not repeat")
    limits = spec["limits"]
    _exact_keys(limits, tuple(LIMIT_RANGES), "SPEC.limits")
    normalized_limits = {}
    for key, (minimum, maximum) in LIMIT_RANGES.items():
        value = _plain_int(limits[key], f"limits.{key}")
        if not minimum <= value <= maximum:
            raise InvestigationError(
                f"limits.{key} must be between {minimum} and {maximum}")
        normalized_limits[key] = value
    return {"messages": sorted(normalized_messages),
            "indicators": sorted(normalized_indicators),
            "limits": normalized_limits}


def _load_spec(path):
    return parse_spec(jsonio.load(path))


# ---------------------------------------------------------- evidence snapshot --

def _open_snapshot(db_path):
    """One read-only connection over one committed snapshot."""
    target = Path(db_path)
    if not target.is_file():
        raise InvestigationError(f"vault does not exist: {db_path}")
    try:
        db = connect_readonly(db_path)
    except sqlite3.Error as exc:
        raise InvestigationError(f"not a mailroom vault: {db_path}") from exc
    try:
        row = db.execute(
            "SELECT value FROM vault_meta WHERE key='format'").fetchone()
    except sqlite3.Error as exc:
        db.close()
        raise InvestigationError(f"not a mailroom vault: {db_path}") from exc
    if row is None or row[0] != VAULT_FORMAT:
        db.close()
        raise InvestigationError(f"not a mailroom vault: {db_path}")
    db.execute("BEGIN")
    return db


def _verified_message(db, message_id):
    """Re-parse one archived message and prove its stored attachment rows.

    Returns ``(source_sha256, [attachment, ...])`` where each attachment still
    carries its transfer-decoded payload.  Any missing/purged message or any
    mismatch between the re-parsed MIME content and ``vault_attachments`` is an
    evidence-integrity error that fails the whole command.  Only the current
    message's decoded payloads are resident at any time; the caller releases
    them before moving to the next message.
    """
    row = db.execute(
        "SELECT status,source_sha256,source_bytes FROM vault_messages "
        "WHERE id=?", (message_id,)).fetchone()
    if row is None or row["status"] != "live" \
            or row["source_bytes"] is None:
        raise InvestigationError(
            f"message is not a current live message: {message_id}")
    raw = bytes(row["source_bytes"])
    if hashlib.sha256(raw).hexdigest() != row["source_sha256"]:
        raise InvestigationError(
            f"stored source bytes fail their SHA256 check: {message_id}")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # malformed archived content is integrity loss
        raise InvestigationError(
            f"archived message no longer parses as MIME: {message_id}") from exc
    attachments = []
    for part_number, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if not filename and part.get_content_disposition() != "attachment":
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as exc:
            raise InvestigationError(
                f"attachment transfer decoding failed: {message_id}") from exc
        attachments.append({
            "part": part_number,
            "filename": filename,
            "media_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "payload": payload,
        })
    stored = [dict(item) for item in db.execute(
        "SELECT part,filename,media_type,size_bytes,sha256 "
        "FROM vault_attachments WHERE message_id=? ORDER BY part",
        (message_id,))]
    actual = [{key: item[key] for key in
               ("part", "filename", "media_type", "size_bytes", "sha256")}
              for item in attachments]
    if stored != actual:
        raise InvestigationError(
            "vault_attachments do not match the re-parsed archived message: "
            + message_id)
    return row["source_sha256"], attachments


# --------------------------------------------------------------- ZIP walking --

def _is_zip_name(filename):
    return filename is not None and filename.lower().endswith(".zip")


def _is_container(attachment):
    return attachment["media_type"] == "application/zip" \
        or _is_zip_name(attachment["filename"])


class _BlobStaging:
    """Delivery-only sink: one private temp file per in-flight leaf.

    Matched leaves are promoted to ``blobs/<sha256>`` once their full bytes are
    verified; unmatched temp files are dropped immediately.  The directory is
    private to one command and always removed on failure.
    """

    def __init__(self, parent):
        self.dir = Path(tempfile.mkdtemp(prefix=".delivery-stage-", dir=parent))
        (self.dir / "blobs").mkdir()
        self._handles = {}

    def writer(self, token):
        fd, path = tempfile.mkstemp(prefix=".leaf-", dir=self.dir)
        handle = os.fdopen(fd, "wb")
        self._handles[token] = (handle, path)
        return handle

    def commit(self, token, digest):
        handle, path = self._handles.pop(token)
        handle.close()
        target = self.dir / "blobs" / digest
        if not target.exists():
            os.link(path, target)
        os.unlink(path)

    def discard(self, token):
        handle, path = self._handles.pop(token)
        handle.close()
        os.unlink(path)

    def abandon(self, token):
        """Cleanup hook for interrupted reads; no-op once finalized."""
        pending = self._handles.pop(token, None)
        if pending is not None:
            handle, path = pending
            handle.close()
            os.unlink(path)

    @property
    def blob_dir(self):
        return self.dir / "blobs"

    @property
    def blob_names(self):
        return {path.name for path in self.blob_dir.iterdir()}

    def destroy(self):
        for handle, path in list(self._handles.values()):
            handle.close()
        shutil.rmtree(self.dir, ignore_errors=True)


class _RootScanner:
    """Per-top-level-attachment budgeted, streaming ZIP traversal."""

    def __init__(self, limits, indicators, temp_parent, staging=None):
        self.max_depth = limits["max_depth"]
        self.max_members = limits["max_members"]
        self.max_expanded = limits["max_expanded_bytes"]
        self.indicators = indicators
        self.temp_parent = temp_parent
        self.staging = staging
        self.leaves = []
        self.issue = None
        self.members_seen = 0
        self.expanded = 0
        self._token = 0

    def _next_token(self):
        self._token += 1
        return self._token

    def _charge(self, amount):
        """Add actually read decompressed bytes; equality with the cap is OK."""
        self.expanded += amount
        return self.expanded > self.max_expanded

    def walk_root(self, attachment):
        payload = attachment["payload"]
        if not _is_container(attachment):
            # Top-level ordinary leaf: its archived bytes count against the
            # expanded-byte budget and an overrun uses the empty root path.
            if len(payload) > self.max_expanded:
                self.issue = {"path": [], "reason": "byte_limit"}
                return
            digest = hashlib.sha256(payload).hexdigest()
            self._record_leaf([], attachment["filename"], len(payload), digest,
                              payload)
            return
        try:
            root_zip = zipfile.ZipFile(io.BytesIO(payload))
        except (zipfile.BadZipFile, OSError) as exc:
            # A node declared to be a ZIP never degrades to an ordinary leaf.
            self.issue = {"path": [], "reason": "invalid_zip"}
            if isinstance(exc, OSError) and not isinstance(exc, zipfile.BadZipFile):
                raise
            return
        with root_zip:
            self._walk_zip(root_zip, [], 1)

    def _walk_zip(self, archive, path, depth):
        for index, info in enumerate(archive.infolist(), start=1):
            member_path = path + [index]
            # Fixed check order: member budget first, then encryption flag,
            # then compression method, then the actual read.
            self.members_seen += 1
            if self.members_seen > self.max_members:
                raise _Issue(member_path, "member_limit")
            if info.flag_bits & 0x1:
                raise _Issue(member_path, "encrypted")
            if info.compress_type not in SUPPORTED_METHODS:
                raise _Issue(member_path, "unsupported_compression")
            if info.is_dir():
                if info.file_size != 0:
                    raise _Issue(member_path, "invalid_zip")
                continue
            self._read_member(archive, info, member_path, depth)
            if self.issue is not None:
                return

    def _read_member(self, archive, info, member_path, depth):
        nested = _is_zip_name(info.filename)
        hasher = hashlib.sha256()
        token = self._next_token()
        handle = None
        temp_path = None
        size = 0
        try:
            if nested:
                fd, temp_path = tempfile.mkstemp(prefix=".nested-zip-",
                                                 dir=self.temp_parent)
                handle = os.fdopen(fd, "wb")
            elif self.staging is not None:
                handle = self.staging.writer(token)
            try:
                with archive.open(info, "r") as member:
                    while True:
                        # When the remaining budget is smaller than the window,
                        # read at most one byte past the cap so the over-read is
                        # exactly the single byte that proves the limit.
                        want = CHUNK
                        room = self.max_expanded - self.expanded
                        if room < want:
                            want = max(room + 1, 1)
                        chunk = member.read(want)
                        if not chunk:
                            break
                        size += len(chunk)
                        hasher.update(chunk)
                        if self._charge(len(chunk)):
                            raise _Issue(member_path, "byte_limit")
                        if handle is not None:
                            handle.write(chunk)
                # Reaching here means EOF, full decompression and the CRC check
                # all succeeded (zipfile verifies CRC when the member closes).
            except _Issue:
                raise
            except _ZIP_ERRORS as exc:
                raise _Issue(member_path, "invalid_zip") from exc
            digest = hasher.hexdigest()
            if nested:
                handle.close()
                handle = None
                # Depth is checked only when the nested container is about to be
                # opened, after its own bytes were fully read and charged.
                if depth + 1 > self.max_depth:
                    raise _Issue(member_path, "depth_limit")
                try:
                    with zipfile.ZipFile(temp_path) as child:
                        self._walk_zip(child, member_path, depth + 1)
                except (zipfile.BadZipFile, OSError) as exc:
                    if isinstance(exc, OSError) \
                            and not isinstance(exc, zipfile.BadZipFile):
                        raise
                    raise _Issue(member_path, "invalid_zip") from exc
            else:
                self._record_leaf(member_path, info.filename, size, digest, None,
                                  token=token)
        finally:
            if handle is not None:
                handle.close()
            if nested and temp_path is not None and os.path.exists(temp_path):
                os.unlink(temp_path)
            elif not nested and self.staging is not None:
                # An interrupted staged leaf must not linger in the staging set.
                self.staging.abandon(token)

    def _record_leaf(self, path, filename, size, digest, payload, token=None):
        matched = digest in self.indicators
        if self.staging is not None:
            if payload is not None:  # top-level ordinary leaf
                if matched:
                    self._stage_bytes(digest, payload)
            elif matched:
                self.staging.commit(token, digest)
            else:
                self.staging.discard(token)
        self.leaves.append({"path": list(path), "filename": filename,
                            "size_bytes": size, "sha256": digest,
                            "matched": matched})

    def _stage_bytes(self, digest, payload):
        target = self.staging.dir / "blobs" / digest
        if target.exists():
            return
        fd, temp_name = tempfile.mkstemp(prefix=".leaf-", dir=self.staging.dir)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
            os.link(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def run(self, attachment):
        try:
            self.walk_root(attachment)
        except _Issue as problem:
            self.issue = {"path": problem.path, "reason": problem.reason}
        return self.leaves, self.issue


# ------------------------------------------------------------- investigation --

def _build_report(db_path, spec, staging=None):
    """Investigate one validated SPEC against one read-only snapshot.

    Messages are handled one at a time and their decoded attachment payloads
    are released before the next message is parsed, so resident expanded
    content never grows with the number of selected messages.
    """
    db = _open_snapshot(db_path)
    temp_root = tempfile.mkdtemp(prefix=".investigate-")
    try:
        try:
            vault_id = _vault_id(db)
            # Whole-scope attachment cap from metadata only, so an over-limit
            # scope is refused without decoding or truncating any payload.
            placeholders = ",".join("?" for _ in spec["messages"])
            total_attachments = db.execute(
                f"SELECT COUNT(*) FROM vault_attachments "
                f"WHERE message_id IN ({placeholders})",
                spec["messages"]).fetchone()[0]
            if total_attachments > MAX_TOP_ATTACHMENTS:
                raise InvestigationError(
                    f"investigation supports at most {MAX_TOP_ATTACHMENTS} "
                    "top-level attachments in total")
            roots = []
            messages = []
            for message_id in spec["messages"]:
                source_sha256, attachments = _verified_message(db, message_id)
                messages.append({"message_id": message_id,
                                 "source_sha256": source_sha256})
                try:
                    for attachment in attachments:
                        scanner = _RootScanner(spec["limits"],
                                               frozenset(spec["indicators"]),
                                               temp_root, staging)
                        leaves, issue = scanner.run(attachment)
                        if issue is None:
                            status = "matched" if any(leaf["matched"]
                                                      for leaf in leaves) \
                                else "clear"
                        else:
                            status = "indeterminate"
                        roots.append({
                            "message_id": message_id,
                            "part": attachment["part"],
                            "filename": attachment["filename"],
                            "media_type": attachment["media_type"],
                            "size_bytes": attachment["size_bytes"],
                            "sha256": attachment["sha256"],
                            "status": status,
                            "issue": issue,
                            "leaves": leaves,
                        })
                finally:
                    # Drop this message's decoded payloads immediately; only
                    # metadata and the finished leaf records remain.
                    for attachment in attachments:
                        attachment["payload"] = None
            roots.sort(key=lambda root: (root["message_id"], root["part"]))
            report = {
                "format": REPORT_FORMAT,
                "vault": vault_id,
                "spec": spec,
                "messages": messages,
                "roots": roots,
            }
            return report
        finally:
            db.rollback()
            db.close()
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def _publish_report(path, payload):
    target = Path(path)
    if target.exists() or target.is_symlink():
        raise InvestigationError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".report-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        os.link(temp_name, target)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def investigate(db_path, spec_path, output_path):
    """Read-only investigation; publish a canonical report to a fresh path."""
    spec = _load_spec(spec_path)
    report = _build_report(db_path, spec)
    payload = _canonical(report)
    if len(payload) > MAX_REPORT_BYTES:
        raise InvestigationError(
            "complete report exceeds 8,000,000 bytes; nothing was published")
    _publish_report(output_path, payload)
    return {"vault": report["vault"],
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload)}


# ------------------------------------------------------------------ delivery --

def _validate_report_structure(report):
    _exact_keys(report, ("format", "vault", "spec", "messages", "roots"),
                "report")
    if report["format"] != REPORT_FORMAT:
        raise InvestigationError(f"report.format must be {REPORT_FORMAT}")
    if not isinstance(report["vault"], str) or not report["vault"]:
        raise InvestigationError("report.vault must be a nonempty string")
    parse_spec(report["spec"])
    messages = report["messages"]
    if not isinstance(messages, list):
        raise InvestigationError("report.messages must be an array")
    previous = None
    for entry in messages:
        _exact_keys(entry, ("message_id", "source_sha256"), "report.messages[]")
        identifier(entry["message_id"], "report message_id")
        if not isinstance(entry["source_sha256"], str) \
                or DIGEST.fullmatch(entry["source_sha256"]) is None:
            raise InvestigationError("report source_sha256 must be 64 hex digits")
        if previous is not None and entry["message_id"] <= previous:
            raise InvestigationError("report.messages must be unique and sorted")
        previous = entry["message_id"]
    roots = report["roots"]
    if not isinstance(roots, list):
        raise InvestigationError("report.roots must be an array")
    previous = None
    for root in roots:
        _exact_keys(root, ("message_id", "part", "filename", "media_type",
                           "size_bytes", "sha256", "status", "issue", "leaves"),
                    "report.roots[]")
        identifier(root["message_id"], "report root message_id")
        _plain_int(root["part"], "root.part")
        if root["filename"] is not None and not isinstance(root["filename"], str):
            raise InvestigationError("root.filename must be a string or null")
        if not isinstance(root["media_type"], str) or not root["media_type"]:
            raise InvestigationError("root.media_type must be a nonempty string")
        _plain_int(root["size_bytes"], "root.size_bytes")
        if DIGEST.fullmatch(root["sha256"]) is None:
            raise InvestigationError("root.sha256 must be 64 hex digits")
        key = (root["message_id"], root["part"])
        if previous is not None and key <= previous:
            raise InvestigationError("report.roots must be sorted and unique")
        previous = key
        if root["status"] not in ("matched", "clear", "indeterminate"):
            raise InvestigationError("root.status has an invalid value")
        if root["status"] == "indeterminate":
            _exact_keys(root["issue"], ("path", "reason"), "root.issue")
            if not isinstance(root["issue"]["path"], list) \
                    or any(type(x) is not int or x < 1
                           for x in root["issue"]["path"]):
                raise InvestigationError("root.issue.path must be positive ints")
            if root["issue"]["reason"] not in ISSUE_REASONS:
                raise InvestigationError("root.issue.reason is invalid")
        elif root["issue"] is not None:
            raise InvestigationError("only indeterminate roots carry an issue")
        leaves = root["leaves"]
        if not isinstance(leaves, list):
            raise InvestigationError("root.leaves must be an array")
        for leaf in leaves:
            _exact_keys(leaf, ("path", "filename", "size_bytes", "sha256",
                               "matched"), "leaf")
            if not isinstance(leaf["path"], list) \
                    or any(type(x) is not int or x < 1 for x in leaf["path"]):
                raise InvestigationError("leaf.path must be an array of positive ints")
            if leaf["filename"] is not None and not isinstance(leaf["filename"], str):
                raise InvestigationError("leaf.filename must be a string or null")
            _plain_int(leaf["size_bytes"], "leaf.size_bytes")
            if DIGEST.fullmatch(leaf["sha256"]) is None:
                raise InvestigationError("leaf.sha256 must be 64 hex digits")
            if not isinstance(leaf["matched"], bool):
                raise InvestigationError("leaf.matched must be a boolean")


def deliver(db_path, report_path, report_sha256, output_dir):
    """Verify an approved report and publish matched leaf blobs once."""
    if not isinstance(report_sha256, str) or DIGEST.fullmatch(report_sha256) is None:
        raise InvestigationError(
            "report-sha256 must be 64 lowercase hexadecimal digits")
    raw = Path(report_path).read_bytes()
    if len(raw) > MAX_REPORT_BYTES:
        raise InvestigationError("report exceeds 8,000,000 bytes")
    if hashlib.sha256(raw).hexdigest() != report_sha256:
        raise InvestigationError(
            "report file digest does not match the approved digest")
    try:
        submitted = json.loads(raw, object_pairs_hook=jsonio._pairs,
                               parse_constant=jsonio._constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvestigationError("report is not valid strict JSON") from exc
    _validate_report_structure(submitted)
    spec = submitted["spec"]

    target = Path(output_dir)
    if target.exists() or target.is_symlink():
        raise InvestigationError(f"delivery directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = _BlobStaging(target.parent)
    try:
        expected = _build_report(db_path, spec, staging=staging)
        if expected["vault"] != submitted["vault"]:
            raise InvestigationError(
                "report vault identity does not match the current vault")
        if expected != submitted:
            raise InvestigationError(
                "report does not match a fresh investigation of the current sources")
        if any(root["status"] == "indeterminate" for root in expected["roots"]):
            raise InvestigationError(
                "approved scope is not fully investigated; delivery is refused")

        occurrences = []
        for root in expected["roots"]:
            for leaf in root["leaves"]:
                if leaf["matched"]:
                    occurrences.append({
                        "message_id": root["message_id"],
                        "source_sha256": next(
                            item["source_sha256"] for item in expected["messages"]
                            if item["message_id"] == root["message_id"]),
                        "part": root["part"],
                        "path": leaf["path"],
                        "sha256": leaf["sha256"],
                    })
        occurrences.sort(key=lambda item: (item["message_id"], item["part"],
                                           item["path"]))
        blob_rows = []
        for digest in sorted(staging.blob_names):
            blob = staging.blob_dir / digest
            if blob.name != digest or not blob.is_file():
                raise InvestigationError("staged blob is missing")
            data = blob.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise InvestigationError("staged blob fails its SHA256 check")
            expected_size = next(
                leaf["size_bytes"] for root in expected["roots"]
                for leaf in root["leaves"]
                if leaf["matched"] and leaf["sha256"] == digest)
            if len(data) != expected_size:
                raise InvestigationError("staged blob fails its recorded length")
            blob_rows.append({"sha256": digest, "size_bytes": len(data)})
        expected_digests = {item["sha256"] for item in occurrences}
        if staging.blob_names != expected_digests:
            raise InvestigationError("staged blob set does not match the report")
        manifest = {
            "format": DELIVERY_FORMAT,
            "vault": expected["vault"],
            "report_sha256": report_sha256,
            "blobs": blob_rows,
            "occurrences": occurrences,
        }
        manifest_payload = _canonical(manifest)
        manifest_path = staging.dir / "manifest.json"
        manifest_path.write_bytes(manifest_payload)
        # Re-open the manifest as an outside reader would and confirm the bytes.
        if manifest_path.read_bytes() != manifest_payload:
            raise InvestigationError("manifest failed its final verification")
        # Everything under the private staging directory is now verified; only
        # now does the delivery name become visible.
        os.rename(staging.dir, target)
        staging = None
        return {"vault": expected["vault"],
                "report_sha256": report_sha256,
                "blob_count": len(blob_rows),
                "occurrence_count": len(occurrences)}
    finally:
        if staging is not None:
            staging.destroy()
