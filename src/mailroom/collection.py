"""Multi-custodian collection intake for an existing vault.

A manifest describes independent collection packages.  Each package is one
all-or-nothing bundle of source provenance: a package may only be archived
whole, and its value is counted whole.  The command chooses the globally best
set of complete packages (maximum total value, then maximum package count,
then lexicographically smallest package ID array), then archives every new
identity of that set together with the source corroboration of every selected
package.  Nothing from an unselected package is written.

The module adds its own persistent tables on demand.  Tables are created in
the same transaction as the first successful intake, so a failed command
leaves the database byte-identical to the previous complete state.
"""
import json
import os
import sqlite3
from pathlib import Path

from . import io as jsonio
from .parse import identifier, read_folder
from .vault import (_ingest_messages, _object_id, _open_vault_readonly,
                    _transact, _vault_id, refuse_if_recovered)

MAX_PACKAGES = 18
MAX_PACKAGE_FILES = 200
MAX_TOTAL_FILES = 600
MAX_TOTAL_BYTES = 40_000_000
MAX_VALUE = 1_000_000

COLLECTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_collection_intakes (
 intake_id TEXT PRIMARY KEY,
 request TEXT NOT NULL,
 receipt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_collection_sources (
 intake_id TEXT NOT NULL,
 package_id TEXT NOT NULL,
 custodian TEXT NOT NULL,
 value INTEGER NOT NULL,
 message_id TEXT NOT NULL,
 source_sha256 TEXT NOT NULL,
 PRIMARY KEY (intake_id, package_id, message_id)
);
CREATE INDEX IF NOT EXISTS vault_collection_sources_message
 ON vault_collection_sources(message_id);
"""


def _exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{label} must be an object with exactly these keys: "
                         + ", ".join(sorted(keys)))


def _plain_int(value, label, minimum, maximum):
    # bool is an int subclass and must never pass as a value
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


# ------------------------------------------------------------- manifest input --

def _load_manifest(path):
    """Read every package completely before any vault state is inspected."""
    manifest = jsonio.load(path)
    _exact_keys(manifest, ("intake_id", "packages"), "MANIFEST")
    intake_id = _object_id(manifest["intake_id"], "intake_id")
    entries = manifest["packages"]
    if not isinstance(entries, list) or not (1 <= len(entries) <= MAX_PACKAGES):
        raise ValueError(f"MANIFEST.packages must contain 1..{MAX_PACKAGES} objects")
    base = Path(os.path.abspath(path)).parent
    packages, seen_ids, seen_files, seen_bytes = [], set(), 0, 0
    for entry in entries:
        _exact_keys(entry, ("package_id", "custodian", "value", "source"),
                    "MANIFEST.packages[]")
        package_id = _object_id(entry["package_id"], "package_id")
        custodian = _object_id(entry["custodian"], "custodian")
        value = _plain_int(entry["value"], "value", 1, MAX_VALUE)
        if package_id in seen_ids:
            raise ValueError(f"duplicate package_id in manifest: {package_id}")
        seen_ids.add(package_id)
        source = entry["source"]
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a nonempty directory path")
        folder = Path(source)
        if not folder.is_absolute():
            folder = base / folder
        messages = read_folder(folder)
        if len(messages) > MAX_PACKAGE_FILES:
            raise ValueError(
                f"package must have 1..{MAX_PACKAGE_FILES} .eml files: {package_id}")
        # File occurrences and raw bytes are counted per package, even when two
        # packages point at the same directory.
        seen_files += len(messages)
        seen_bytes += sum(len(message["raw"]) for message in messages.values())
        if seen_files > MAX_TOTAL_FILES:
            raise ValueError(f"packages exceed {MAX_TOTAL_FILES} total message occurrences")
        if seen_bytes > MAX_TOTAL_BYTES:
            raise ValueError("packages exceed 40 MB of raw source bytes")
        packages.append({
            "package_id": package_id,
            "custodian": custodian,
            "value": value,
            "messages": messages,
            "ids": tuple(sorted(messages)),
        })
    packages.sort(key=lambda package: package["package_id"])
    return intake_id, packages, _canonical_request(intake_id, packages)


def _canonical_request(intake_id, packages):
    """Package order, file order/names and paths never enter this identity."""
    document = {
        "intake_id": intake_id,
        "packages": [
            {
                "package_id": package["package_id"],
                "custodian": package["custodian"],
                "value": package["value"],
                "messages": [
                    {"message_id": message_id,
                     "sha256": package["messages"][message_id]["sha256"]}
                    for message_id in sorted(package["messages"])
                ],
            }
            for package in sorted(packages, key=lambda package: package["package_id"])
        ],
    }
    return json.dumps(document, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


# -------------------------------------------------------- graph / search core --

def _canonical_cycle(cycle):
    """Rotate a directed cycle so it starts at its smallest ID, then close it."""
    start = min(range(len(cycle)), key=lambda index: cycle[index])
    rotated = cycle[start:] + cycle[:start]
    return tuple(rotated + [rotated[0]])


def _baseline_terminals(parents):
    """Terminal of every baseline identity's chain of immutable parent links.

    Baseline parents never change during one intake, so the first ancestor that
    is not a baseline identity (an external missing ID or a node some package
    adds) can be found once instead of re-walked for every candidate set.
    """
    terminals = {}
    for start in parents:
        if start in terminals:
            continue
        path, index = [], {}
        cursor = start
        while cursor in parents and cursor not in index and cursor not in terminals:
            index[cursor] = len(path)
            path.append(cursor)
            cursor = parents[cursor]
        if cursor in index:  # defensive: a valid vault never stores a cycle
            raise ValueError(f"reply cycle at {path[index[cursor]]}")
        terminal = terminals.get(cursor, cursor)
        for node in path:
            terminals[node] = terminal
    return terminals


def _effective(parents, baseline_nodes, terminals, cursor):
    """Next non-baseline ancestor reached from a new identity.

    Baseline nodes cannot themselves complete a new cycle, so their chain is
    compressed to its terminal.  The compressed edges are what the cycle search
    walks; the terminal may itself be a new identity or an external ID.
    """
    while cursor is not None and cursor in baseline_nodes:
        cursor = terminals[cursor]
    return cursor


def _has_cycle(parents, baseline_nodes, terminals, starts):
    """True when the joint baseline/new parent graph closes a cycle.

    Only newly-added identities can complete a cycle, so the search walks only
    those (baseline parents are immutable).
    """
    resolved = set()
    for start in starts:
        if start in resolved:
            continue
        path, index = [], {}
        cursor = start
        while cursor is not None:
            cursor = _effective(parents, baseline_nodes, terminals, cursor)
            if cursor is None or cursor not in parents:
                break
            if cursor in index:
                return True
            if cursor in resolved:
                break
            index[cursor] = len(path)
            path.append(cursor)
            cursor = parents[cursor]
        resolved.update(path)
    return False


def _expand_cycle(cycle, parents, baseline_nodes):
    """Splice the immutable baseline chains back into a compressed cycle."""
    actual = []
    for node in cycle:
        actual.append(node)
        parent = parents[node]
        while parent is not None and parent in baseline_nodes:
            actual.append(parent)
            parent = parents[parent]
    return _canonical_cycle(actual)


def _cycles(parents, baseline_nodes, terminals, starts):
    """All canonical cycles in the joint graph, each starting at its smallest ID."""
    cycles, resolved = set(), set()
    for start in starts:
        if start in resolved:
            continue
        path, index = [], {}
        cursor = start
        while cursor is not None:
            cursor = _effective(parents, baseline_nodes, terminals, cursor)
            if cursor is None or cursor not in parents:
                break
            if cursor in index:
                cycles.add(_expand_cycle(path[index[cursor]:], parents, baseline_nodes))
                break
            if cursor in resolved:
                break
            index[cursor] = len(path)
            path.append(cursor)
            cursor = parents[cursor]
        resolved.update(path)
    return cycles


def _package_conflicts(package, baseline):
    """Message-IDs whose raw version differs from an already archived identity."""
    messages = package["messages"]
    return sorted(message_id for message_id in package["ids"]
                  if message_id in baseline
                  and baseline[message_id]["source_sha256"] != messages[message_id]["sha256"])


def _solve(baseline, packages):
    """Exact maximum-value (then count, then lexicographic) package selection.

    Feasible package sets are downward closed: a conflicting or cyclic set
    cannot become feasible by adding another package.  The DFS therefore only
    descends into feasible subsets, visits every feasible subset exactly once,
    and prunes with the suffix value bound.  Packages are tried in ascending
    package_id with inclusion first, so the lexicographic tie-break is reached
    early; the comparison is nevertheless explicit, not order-dependent.
    """
    conflicts = {package["package_id"]: _package_conflicts(package, baseline)
                 for package in packages}
    eligible = [package for package in packages
                if not conflicts[package["package_id"]]]
    count = len(eligible)
    incompatible = [0] * count
    for left in range(count):
        first = eligible[left]
        for right in range(left + 1, count):
            second = eligible[right]
            for message_id in first["ids"]:
                other = second["messages"].get(message_id)
                if other is not None and other["sha256"] != first["messages"][message_id]["sha256"]:
                    incompatible[left] |= 1 << right
                    incompatible[right] |= 1 << left
                    break
    suffix_value = [0] * (count + 1)
    for index in range(count - 1, -1, -1):
        suffix_value[index] = suffix_value[index + 1] + eligible[index]["value"]

    parents = {message_id: row["parent_id"] for message_id, row in baseline.items()}
    baseline_nodes = set(parents)
    terminals = _baseline_terminals(parents)
    new_nodes = set()

    chosen = []
    best = {"value": 0, "count": 0, "ids": ()}

    def consider(value):
        candidate_ids = tuple(chosen)
        key = (value, len(candidate_ids))
        best_key = (best["value"], best["count"])
        if key > best_key or (key == best_key and candidate_ids < best["ids"]):
            best.update(value=value, count=len(candidate_ids), ids=candidate_ids)

    def walk(index, mask, value):
        bound = value + suffix_value[index]
        if bound < best["value"]:
            return
        if bound == best["value"] and len(chosen) + (count - index) < best["count"]:
            return  # even taking every remaining package cannot tie on count
        if index == count:
            consider(value)
            return
        package = eligible[index]
        if not mask & incompatible[index]:
            new_ids = [message_id for message_id in package["ids"]
                       if message_id not in parents]
            for message_id in new_ids:
                parents[message_id] = package["messages"][message_id]["parent_id"]
                new_nodes.add(message_id)
            try:
                if not _has_cycle(parents, baseline_nodes, terminals, new_nodes):
                    chosen.append(package["package_id"])
                    try:
                        walk(index + 1, mask | (1 << index), value + package["value"])
                    finally:
                        chosen.pop()
            finally:
                for message_id in new_ids:
                    del parents[message_id]
                    new_nodes.discard(message_id)
        walk(index + 1, mask, value)  # leave this package out

    walk(0, 0, 0)
    selected_ids = set(best["ids"])
    selected = [package for package in packages
                if package["package_id"] in selected_ids]
    selected.sort(key=lambda package: package["package_id"])
    return selected, conflicts


def _witness_cycle(package, baseline, selected):
    """Canonical lexicographically smallest reply cycle a package would close."""
    parents = {message_id: row["parent_id"] for message_id, row in baseline.items()}
    baseline_nodes = set(parents)
    terminals = _baseline_terminals(parents)
    for other in selected:
        for message_id in other["ids"]:
            if message_id not in parents:
                parents[message_id] = other["messages"][message_id]["parent_id"]
    for message_id in package["ids"]:
        if message_id not in parents:
            parents[message_id] = package["messages"][message_id]["parent_id"]
    new_nodes = set(parents) - baseline_nodes
    cycles = _cycles(parents, baseline_nodes, terminals, new_nodes)
    if not cycles:
        raise ValueError("internal selection error: package was actually selectable")
    return list(min(cycles))


def _excluded(package, baseline, selected, selected_sha, conflicts):
    archived = conflicts[package["package_id"]]
    if archived:
        return {"package_id": package["package_id"],
                "reason": "archived_identity_conflict", "witness": archived}
    messages = package["messages"]
    divergent = sorted(message_id for message_id in package["ids"]
                       if message_id in selected_sha
                       and selected_sha[message_id] != messages[message_id]["sha256"])
    if divergent:
        return {"package_id": package["package_id"],
                "reason": "selected_identity_conflict", "witness": divergent}
    return {"package_id": package["package_id"], "reason": "reply_cycle",
            "witness": _witness_cycle(package, baseline, selected)}


def _receipt(vault_id, intake_id, baseline, packages, selected, conflicts):
    selected_ids = {package["package_id"] for package in selected}
    total_value = sum(package["value"] for package in selected)
    union = set()
    for package in selected:
        union.update(package["ids"])
    inserted, unchanged_live, ignored_purged = [], [], []
    for message_id in sorted(union):
        row = baseline.get(message_id)
        if row is None:
            inserted.append(message_id)
        elif row["status"] == "live":
            unchanged_live.append(message_id)
        else:
            ignored_purged.append(message_id)
    selected_sha = {}
    for package in selected:
        for message_id in package["ids"]:
            selected_sha[message_id] = package["messages"][message_id]["sha256"]
    excluded = [_excluded(package, baseline, selected, selected_sha, conflicts)
                for package in packages
                if package["package_id"] not in selected_ids]
    excluded.sort(key=lambda item: item["package_id"])
    return {
        "vault": vault_id,
        "intake_id": intake_id,
        "total_value": total_value,
        "selected_packages": sorted(selected_ids),
        "inserted": inserted,
        "unchanged_live": unchanged_live,
        "ignored_purged": ignored_purged,
        "excluded": excluded,
    }


# -------------------------------------------------------------- transactions --

def _ensure_collection_tables(db):
    # Plain execute() rather than executescript: executescript would commit the
    # surrounding transaction.  DDL therefore rolls back with the first intake.
    for statement in COLLECTION_SCHEMA.split(";"):
        if statement.strip():
            db.execute(statement)
    db.execute("INSERT OR IGNORE INTO vault_meta(key,value) VALUES('collection_schema','1')")


def _stored_intake(db, intake_id):
    exists = db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vault_collection_intakes'"
    ).fetchone()
    if exists is None:
        return None
    return db.execute(
        "SELECT request, receipt FROM vault_collection_intakes WHERE intake_id=?",
        (intake_id,)).fetchone()


def collection_import(db_path, manifest_path):
    refuse_if_recovered(db_path)
    intake_id, packages, request = _load_manifest(manifest_path)

    def operation(db):
        stored = _stored_intake(db, intake_id)
        if stored is not None:
            # Replay identity is decided before looking at the current archive:
            # later holds, purges or intakes cannot change the first result.
            if stored["request"] != request:
                raise ValueError(
                    f"intake_id already recorded with a different request: {intake_id}")
            return json.loads(stored["receipt"])

        baseline = {row["id"]: row for row in db.execute(
            "SELECT id,parent_id,status,source_sha256 FROM vault_messages")}
        selected, conflicts = _solve(baseline, packages)
        vault_id = _vault_id(db)
        receipt = _receipt(vault_id, intake_id, baseline, packages, selected, conflicts)

        _ensure_collection_tables(db)
        union = {}
        for package in selected:
            for message_id, message in package["messages"].items():
                union.setdefault(message_id, message)
        if union:
            _ingest_messages(db, union)
        for package in selected:
            for message_id in package["ids"]:
                db.execute(
                    "INSERT INTO vault_collection_sources VALUES (?,?,?,?,?,?)",
                    (intake_id, package["package_id"], package["custodian"],
                     package["value"], message_id,
                     package["messages"][message_id]["sha256"]))
        db.execute("INSERT INTO vault_collection_intakes VALUES (?,?,?)",
                   (intake_id, request,
                    json.dumps(receipt, ensure_ascii=False, allow_nan=False)))
        return receipt

    return _transact(db_path, operation)


def collection_show(db_path, intake_id):
    """Read-only first receipt for an intake; never creates tables."""
    _object_id(intake_id, "intake_id")
    db = _open_vault_readonly(db_path)
    try:
        try:
            stored = db.execute(
                "SELECT receipt FROM vault_collection_intakes WHERE intake_id=?",
                (intake_id,)).fetchone()
        except sqlite3.OperationalError as exc:  # no collection tables yet
            raise ValueError(f"unknown intake_id: {intake_id}") from exc
        if stored is None:
            raise ValueError(f"unknown intake_id: {intake_id}")
        return json.loads(stored["receipt"])
    finally:
        db.close()


def vault_provenance(db_path, message_id):
    """Read-only source corroboration for a live or purged identity."""
    message_id = identifier(message_id, "message_id")
    db = _open_vault_readonly(db_path)
    try:
        identity = db.execute("SELECT 1 FROM vault_messages WHERE id=?",
                              (message_id,)).fetchone()
        if identity is None:
            raise ValueError("unknown message ID")
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='vault_collection_sources'").fetchone()
        if exists is None:
            return {"message_id": message_id, "sources": []}
        rows = db.execute(
            "SELECT intake_id,package_id,custodian,value,message_id,source_sha256 "
            "FROM vault_collection_sources WHERE message_id=? "
            "ORDER BY intake_id,package_id", (message_id,)).fetchall()
        return {"message_id": message_id, "sources": [
            {"intake_id": row["intake_id"], "package_id": row["package_id"],
             "custodian": row["custodian"], "value": row["value"],
             "message_id": row["message_id"], "source_sha256": row["source_sha256"]}
            for row in rows]}
    finally:
        db.close()
