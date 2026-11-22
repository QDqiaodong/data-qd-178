import base64
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Recompute the two independent digests used by the README demo and the tests.
# This is deliberately a standalone standard-library script: it parses nothing
# from the vault, it only confirms the fixture bytes did not drift.
EXPECTED_MESSAGE_IDS = {
    "batch1/001-legacy.eml": "<legacy@example.invalid>",
    "batch1/002-crane.eml": "<crane@example.invalid>",
    "batch1/003-reply.eml": "<crane-reply@example.invalid>",
    "batch1/004-supplier.eml": "<supplier@example.invalid>",
    "later/001-late.eml": "<late@example.invalid>",
    "package/001-crane.eml": "<crane@example.invalid>",
}


def message_id(raw):
    head = raw.split(b"\n\n", 1)[0]
    for line in head.splitlines():
        if line.lower().startswith(b"message-id:"):
            return line.split(b":", 1)[1].strip().decode()
    raise SystemExit("missing Message-ID")


def main():
    for name, expected in EXPECTED_MESSAGE_IDS.items():
        raw = (ROOT / name).read_bytes()
        assert message_id(raw) == expected, name
    assert (ROOT / "package/001-crane.eml").read_bytes() == \
        (ROOT / "batch1/002-crane.eml").read_bytes()
    body = (ROOT / "batch1/002-crane.eml").read_bytes()
    # The attachment block survives base64 round-trip to its exact bytes.
    encoded = b"".join(line for line in body.splitlines()
                       if re.fullmatch(rb"[A-Za-z0-9+/=]+", line))
    assert base64.b64decode(encoded) == b"raw bracket photo bytes"
    print(json.dumps({
        "fixtures": sorted(EXPECTED_MESSAGE_IDS),
        "crane_sha256": hashlib.sha256(body).hexdigest(),
    }, indent=2))


if __name__ == "__main__":
    main()
