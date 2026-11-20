"""Read bounded .eml files without fetching or extracting external content."""
import hashlib
import re
from datetime import timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path

IDENTIFIER = re.compile(r"<[^<>\s]+>")


def identifier(value, label):
    result = str(value or "").strip()
    if not IDENTIFIER.fullmatch(result):
        raise ValueError(f"{label} must be one bracketed Message-ID")
    return result


def parse_message(raw, source):
    if len(raw) > 2_000_000:
        raise ValueError(f"message exceeds 2 MB: {source}")
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    if msg.defects:
        raise ValueError(f"malformed MIME message: {source}")
    for header in ("Message-ID", "In-Reply-To", "Date", "From", "Subject"):
        if len(msg.get_all(header, [])) > 1:
            raise ValueError(f"duplicate {header}: {source}")
    message_id = identifier(msg["Message-ID"], "Message-ID")
    parent_id = identifier(msg["In-Reply-To"], "In-Reply-To") if msg["In-Reply-To"] else None
    stamp = parsedate_to_datetime(str(msg["Date"]))
    if stamp.tzinfo is None:
        raise ValueError(f"Date requires a timezone: {source}")
    plain, attachments = [], []
    for number, part in enumerate(msg.walk()):
        if part.defects:
            raise ValueError(f"malformed MIME part: {source}")
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if part.defects:
            raise ValueError(f"malformed content transfer encoding: {source}")
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append({"part": number, "filename": filename,
                                "media_type": part.get_content_type(), "size_bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
        elif part.get_content_type() == "text/plain":
            try:
                plain.append(payload.decode(part.get_content_charset() or "ascii", errors="strict"))
            except (UnicodeError, LookupError) as exc:
                raise ValueError(f"unsupported or invalid text encoding: {source}") from exc
    return {"id": message_id, "parent_id": parent_id, "subject": str(msg["Subject"] or ""),
            "sender": str(msg["From"] or ""), "sent_at": stamp.astimezone(timezone.utc).isoformat(),
            "body": "\n".join(plain), "sha256": hashlib.sha256(raw).hexdigest(),
            "raw": raw, "attachments": attachments}


def read_folder(folder):
    folder = Path(folder)
    if not folder.is_dir() or folder.is_symlink():
        raise ValueError("source must be a real directory")
    paths = sorted(folder.glob("*.eml"))
    if not 1 <= len(paths) <= 2000:
        raise ValueError("source must have 1..2000 immediate .eml files")
    messages = {}
    total = 0
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError("message symlinks are not supported")
        if path.stat().st_size > 2_000_000:
            raise ValueError("message exceeds 2 MB")
        raw = path.read_bytes()
        total += len(raw)
        if total > 40_000_000:
            raise ValueError("source exceeds 40 MB")
        row = parse_message(raw, path.name)
        if row["id"] in messages:
            raise ValueError(f"duplicate Message-ID: {row['id']}")
        messages[row["id"]] = row
    # Resolve reply chains iteratively; an absent parent remains an explicit external root.
    roots = {}
    for key in messages:
        chain, seen, cursor = [], set(), key
        while cursor in messages and cursor not in roots:
            if cursor in seen:
                raise ValueError(f"reply cycle at {cursor}")
            seen.add(cursor)
            chain.append(cursor)
            parent = messages[cursor]["parent_id"]
            if parent is None:
                roots[cursor] = cursor
                break
            cursor = parent
        root = roots.get(cursor, cursor)
        for node in chain:
            roots[node] = root
    for key, row in messages.items():
        row["thread_id"] = roots[key]
    return messages
