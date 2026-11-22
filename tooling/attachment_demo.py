"""Deterministic reference values for the attachment investigation demo.

Run from the repository root with
``PYTHONPATH=src python3 tooling/attachment_demo.py``.  It builds a synthetic
vault containing nested ZIP containers, duplicate names, duplicate physical
content, an encrypted member and an unrelated plain attachment, then prints the
independently computed oracle values (content digests, physical occurrence
paths, report digest, delivery manifest shape).  Nothing here reads values back
from the module under test to compute the expectations: the ZIP layout and
hashes are constructed first, the commands are run second.
"""
import hashlib
import io
import json
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from mailroom import investigate, vault

A = "<case-a@example.invalid>"
B = "<case-b@example.invalid>"
CANONICAL = dict(ensure_ascii=False, sort_keys=True,
                 separators=(",", ":"), allow_nan=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def zip_bytes(entries, encrypted=()):
    import struct
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name)
            zf.writestr(info, data)
    raw = bytearray(buf.getvalue())
    for name in encrypted:
        with zipfile.ZipFile(io.BytesIO(bytes(raw))) as zf:
            info = zf.getinfo(name)
        raw[info.header_offset + 6] |= 0x01  # local general-purpose flags
        cursor = 0
        while cursor < len(raw) - 4:
            if struct.unpack_from("<I", raw, cursor)[0] == 0x02014B50:
                name_len = struct.unpack_from("<H", raw, cursor + 28)[0]
                extra_len = struct.unpack_from("<H", raw, cursor + 30)[0]
                comment_len = struct.unpack_from("<H", raw, cursor + 32)[0]
                if bytes(raw[cursor + 46:cursor + 46 + name_len]) \
                        == name.encode():
                    raw[cursor + 8] |= 0x01  # central general-purpose flags
                    break
                cursor += 46 + name_len + extra_len + comment_len
            else:
                cursor += 1
    return bytes(raw)


def eml(msg_id, attachments):
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = "investigator@example.invalid"
    msg["To"] = "vault@example.invalid"
    msg["Date"] = "Tue, 03 Nov 2026 11:00:00 +0000"
    msg["Message-ID"] = msg_id
    msg["Subject"] = "Attachment case"
    msg.set_content("see attachments")
    for filename, data, ctype in attachments:
        main, sub = ctype.split("/", 1)
        msg.add_attachment(data, maintype=main, subtype=sub, filename=filename)
    return bytes(msg)


def build(root):
    hit = b"shared indicator leaf bytes"
    decoy = b"same member name, different content"
    inner = zip_bytes([("../dup.txt", hit), ("note.txt", b"inner note")])
    good_zip = zip_bytes([
        ("../dup.txt", hit),                  # first physical hit
        ("inner.zip", inner),                 # nested second physical hit
        ("../dup.txt", decoy),                # same name, no match
        ("plain.bin", b"unmatched sibling"),
    ])
    secret = zip_bytes([("secret.bin", b"ciphertext")], encrypted=("secret.bin",))
    mail = root / "mail"
    mail.mkdir()
    (mail / "a.eml").write_bytes(eml(A, [
        ("case.zip", good_zip, "application/zip"),
        ("locked.zip", secret, "application/zip"),
    ]))
    (mail / "b.eml").write_bytes(eml(
        B, [("loose.bin", hit, "application/octet-stream")]))
    db = root / "vault.sqlite"
    vault.init(mail, db)

    spec = {"messages": [B, A], "indicators": [sha(hit)],
            "limits": {"max_depth": 4, "max_members": 2000,
                       "max_expanded_bytes": 1_073_741_824}}
    spec_path = root / "spec.json"
    spec_path.write_bytes(json.dumps(spec, **CANONICAL).encode())
    report_path = root / "report.json"
    summary = investigate.investigate(db, spec_path, report_path)
    report = json.loads(report_path.read_bytes())

    expected_occurrences = [
        {"message_id": A, "part": 2, "path": [1], "sha256": sha(hit)},
        {"message_id": A, "part": 2, "path": [2, 1], "sha256": sha(hit)},
        {"message_id": B, "part": 2, "path": [], "sha256": sha(hit)},
    ]
    values = {
        "indicator_sha256": sha(hit),
        "decoy_sha256": sha(decoy),
        "expected_occurrences": expected_occurrences,
        "root_statuses": {f"{r['message_id']}#part{r['part']}": r["status"]
                          for r in report["roots"]},
        "encrypted_issue": next(
            r["issue"] for r in report["roots"]
            if r["filename"] == "locked.zip"),
        "report_sha256_expected": sha(
            json.dumps(report, **CANONICAL).encode()),
        "report_sha256_published": summary["sha256"],
        "report_bytes": summary["bytes"],
    }

    # The indeterminate root makes delivery refuse; a second report without the
    # encrypted attachment demonstrates the complete delivery path.
    mail2 = root / "mail2"
    mail2.mkdir()
    (mail2 / "a.eml").write_bytes(eml(
        A, [("case.zip", good_zip, "application/zip")]))
    (mail2 / "b.eml").write_bytes(eml(
        B, [("loose.bin", hit, "application/octet-stream")]))
    db2 = root / "vault-complete.sqlite"
    vault.init(mail2, db2)
    report2 = root / "report-complete.json"
    summary2 = investigate.investigate(db2, spec_path, report2)
    delivery = root / "delivery"
    delivered = investigate.deliver(db2, report2, summary2["sha256"], delivery)
    manifest = json.loads((delivery / "manifest.json").read_bytes())
    values["complete_delivery"] = {
        "blob_count": delivered["blob_count"],
        "occurrence_count": delivered["occurrence_count"],
        "blob_files": sorted(p.name for p in (delivery / "blobs").iterdir()),
        "manifest_occurrences": [(o["message_id"], o["part"], o["path"])
                                 for o in manifest["occurrences"]],
        "expected_occurrence_count": 3,
        "blob_verifies": sha((delivery / "blobs" / sha(hit)).read_bytes())
                          == sha(hit),
    }
    return values


def main():
    with tempfile.TemporaryDirectory() as tmp:
        print(json.dumps(build(Path(tmp)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
