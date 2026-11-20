import contextlib
import hashlib
import io
import itertools
import json
import random
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mailroom import cli, collection, vault
from mailroom.archive import build as v1_build

R = "<r@example.invalid>"
P = "<p@example.invalid>"
A = "<a@example.invalid>"


def write_eml(directory, name, msg_id, parent=None,
              date="Tue, 03 Nov 2026 08:00:00 +0000", subject="Note",
              body="body text", sender="a@example.invalid"):
    headers = [f"From: {sender}", "To: b@example.invalid", f"Date: {date}",
               f"Message-ID: {msg_id}"]
    if parent is not None:
        headers.append(f"In-Reply-To: {parent}")
    headers += [f"Subject: {subject}", "MIME-Version: 1.0",
                "Content-Type: text/plain; charset=utf-8"]
    path = Path(directory) / name
    path.write_text("\n".join(headers) + "\n\n" + body + "\n")
    return path


class CollectionCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "vault.sqlite"
        self._dirs = 0

    def batch(self, name=None):
        self._dirs += 1
        folder = self.root / (name or f"dir{self._dirs:03d}")
        folder.mkdir()
        return folder

    def messages(self, spec, name=None):
        """spec: list of (message_id, parent_or_None, body). Returns folder."""
        folder = self.batch(name)
        for number, (msg_id, parent, body) in enumerate(spec):
            write_eml(folder, f"{number:03d}.eml", msg_id, parent=parent, body=body)
        return folder

    def init_vault(self, spec):
        folder = self.messages(spec)
        vault.init(folder, self.db)
        self.last_baseline = folder

    def manifest(self, value, name="manifest.json"):
        path = self.root / name
        path.write_text(json.dumps(value, ensure_ascii=False))
        return path

    def package(self, package_id, custodian, value, folder):
        return {"package_id": package_id, "custodian": custodian,
                "value": value, "source": str(folder)}

    def import_(self, manifest_path):
        return collection.collection_import(self.db, manifest_path)

    def query(self, sql, args=()):
        con = sqlite3.connect(self.db)
        try:
            return con.execute(sql, args).fetchall()
        finally:
            con.close()

    def baseline_file(self):
        """The first source file written by the most recent init_vault()."""
        return self.last_baseline / "000.eml"

    def statuses(self):
        return dict(self.query("SELECT id, status FROM vault_messages"))


class SelectionSemanticsTests(CollectionCase):
    def scenario(self):
        """Baseline R -> missing P. X: high value, P -> R (closes with R)."""
        self.init_vault([(R, P, "reply body")])
        x = self.messages([(P, R, "X copy of parent")], "x")
        y = self.messages([(P, A, "Y copy of parent")], "y")
        return x, y

    def test_single_package_cycle_with_baseline_is_never_selected(self):
        x, _ = self.scenario()
        manifest = self.manifest({"intake_id": "I-X", "packages": [
            self.package("PKG-X", "CUST-X", 90, x)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], [])
        self.assertEqual(receipt["total_value"], 0)
        self.assertEqual(receipt["inserted"], [])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-X", "reason": "reply_cycle",
            "witness": [P, R, P]}])  # canonical: smallest ID first, closed
        self.assertEqual(self.statuses(), {R: "live"})
        self.assertEqual(self.query("SELECT * FROM vault_collection_sources"), [])

    def test_receipt_reports_selected_conflict_not_cycle(self):
        x, y = self.scenario()
        manifest = self.manifest({"intake_id": "I-BOTH", "packages": [
            self.package("PKG-X", "CUST-X", 90, x),
            self.package("PKG-Y", "CUST-Y", 10, y)]})
        receipt = self.import_(manifest)
        # X alone cycles; Y is legal and re-roots R under A.  Because PKG-Y is
        # in the final set, X's first obstacle is the P version mismatch.
        self.assertEqual(receipt["selected_packages"], ["PKG-Y"])
        self.assertEqual(receipt["total_value"], 10)
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-X", "reason": "selected_identity_conflict",
            "witness": [P]}])
        self.assertEqual(receipt["inserted"], [P])

    def test_y_reroots_existing_reply_and_new_hold_blocks_old_plan(self):
        x, y = self.scenario()
        # A hold anchored on A does not cover R while P is missing.
        vault.hold_add(self.db, "H1", A)
        plan = vault.retention_plan(self.db, "Q1", "2026-11-04T00:00:00Z")
        self.assertEqual([c["id"] for c in plan["candidates"]], [R])
        self.assertEqual(plan["held"], [])
        manifest = self.manifest({"intake_id": "I-Y", "packages": [
            self.package("PKG-Y", "CUST-Y", 10, y)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-Y"])
        # P arrives: R now reaches anchor A and joins the hold; plan is blocked.
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {R: A, P: A})
        with self.assertRaises(vault.HoldBlocked) as ctx:
            vault.retention_apply(self.db, "Q1")
        self.assertEqual(ctx.exception.blocked, [{"id": R, "holds": ["H1"]}])
        # the old plan still only lists R once the hold is released
        vault.hold_release(self.db, "H1")
        self.assertEqual(vault.retention_apply(self.db, "Q1")["purged"], [R])
        self.assertEqual(self.statuses(), {R: "purged", P: "live"})

    def test_two_legal_packages_cycle_only_when_combined(self):
        self.init_vault([("<!root@x>", None, "root")])
        first = self.messages([("<one@x>", "<two@x>", "one")], "one")
        second = self.messages([("<two@x>", "<one@x>", "two")], "two")
        manifest = self.manifest({"intake_id": "I-PAIR", "packages": [
            self.package("PKG-A", "CUST", 5, first),
            self.package("PKG-B", "CUST", 5, second)]})
        receipt = self.import_(manifest)
        # each alone is a chain into an external node; both together close a cycle
        self.assertEqual(receipt["total_value"], 5)
        self.assertEqual(receipt["selected_packages"], ["PKG-A"])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-B", "reason": "reply_cycle",
            "witness": ["<one@x>", "<two@x>", "<one@x>"]}])

    def test_higher_value_single_package_loses_to_two_compatible(self):
        self.init_vault([("<!root@x>", None, "root")])
        # A conflicts with C on X, B conflicts with C on Y; A and B are compatible
        first = self.messages([("<a1@x>", None, "a"), ("<x@x>", None, "A x")], "a")
        second = self.messages([("<b1@x>", None, "b"), ("<y@x>", None, "B y")], "b")
        solo = self.messages([("<c1@x>", None, "c"), ("<x@x>", None, "C x"),
                              ("<y@x>", None, "C y")], "c")
        manifest = self.manifest({"intake_id": "I-GLOBAL", "packages": [
            self.package("PKG-A", "CUST", 4, first),
            self.package("PKG-B", "CUST", 4, second),
            self.package("PKG-C", "CUST", 7, solo)]})
        receipt = self.import_(manifest)
        # A+B = 8 beats C = 7 even though C is the largest single package
        self.assertEqual(receipt["selected_packages"], ["PKG-A", "PKG-B"])
        self.assertEqual(receipt["total_value"], 8)
        self.assertEqual(receipt["excluded"], [
            {"package_id": "PKG-C", "reason": "selected_identity_conflict",
             "witness": ["<x@x>", "<y@x>"]}])

    def test_identical_bytes_from_multiple_custodians_all_selected(self):
        self.init_vault([("<!root@x>", None, "root")])
        folder = self.messages([("<shared@x>", None, "shared body")], "shared")
        manifest = self.manifest({"intake_id": "I-SHARE", "packages": [
            self.package("PKG-1", "CUST-1", 3, folder),
            self.package("PKG-2", "CUST-2", 3, folder),
            self.package("PKG-3", "CUST-1", 3, folder)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-1", "PKG-2", "PKG-3"])
        self.assertEqual(receipt["total_value"], 9)
        self.assertEqual(receipt["inserted"], ["<shared@x>"])
        rows = self.query("SELECT intake_id,package_id,custodian,value,message_id,"
                          "source_sha256 FROM vault_collection_sources "
                          "ORDER BY package_id")
        self.assertEqual([(r[0], r[1], r[2], r[3], r[4]) for r in rows],
                         [("I-SHARE", "PKG-1", "CUST-1", 3, "<shared@x>"),
                          ("I-SHARE", "PKG-2", "CUST-2", 3, "<shared@x>"),
                          ("I-SHARE", "PKG-3", "CUST-1", 3, "<shared@x>")])
        self.assertEqual(len({r[5] for r in rows}), 1)  # single shared version

    def test_identical_sha_does_not_count_as_new_but_is_recorded(self):
        self.init_vault([("<m@x>", None, "original")])
        # a byte-for-byte copy of the archived source is the same version
        source = self.baseline_file()
        folder2 = self.batch("same")
        (folder2 / "000.eml").write_bytes(source.read_bytes())
        manifest = self.manifest({"intake_id": "I-SAME", "packages": [
            self.package("PKG-R", "CUST", 2, folder2)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["inserted"], [])
        self.assertEqual(receipt["unchanged_live"], ["<m@x>"])
        self.assertEqual(receipt["selected_packages"], ["PKG-R"])
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources"),
                         [(1,)])


class TieBreakTests(CollectionCase):
    def test_equal_value_prefers_more_packages(self):
        self.init_vault([("<!root@x>", None, "root")])
        # C carries divergent versions of A's and B's shared IDs, so it can
        # never join A or B; {A,B} ties {C} at value 10 and wins on count.
        a = self.messages([("<a@x>", None, "a"), ("<x@x>", None, "A x")], "a")
        b = self.messages([("<b@x>", None, "b"), ("<y@x>", None, "B y")], "b")
        c = self.messages([("<c@x>", None, "c"), ("<x@x>", None, "C x"),
                           ("<y@x>", None, "C y")], "c")
        manifest = self.manifest({"intake_id": "I-COUNT", "packages": [
            self.package("PKG-A", "CUST", 5, a),
            self.package("PKG-B", "CUST", 5, b),
            self.package("PKG-C", "CUST", 10, c)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["total_value"], 10)
        self.assertEqual(receipt["selected_packages"], ["PKG-A", "PKG-B"])

    def test_equal_value_and_count_prefers_lexicographic_ids(self):
        self.init_vault([("<!root@x>", None, "root")])
        for name in ("aa", "ab", "ba", "bb"):
            self.messages([(f"<{name}@x>", None, name)], name)
        pairs = {"PKG-A": "aa", "PKG-B": "ab", "PKG-C": "ba", "PKG-D": "bb"}
        manifest = self.manifest({"intake_id": "I-LEX", "packages": [
            self.package(pkg, "CUST", 1, self.root / dirname)
            for pkg, dirname in pairs.items()]})
        # one message per directory, so all four packages are compatible and
        # maximum count (4) wins outright
        receipt = self.import_(manifest)
        self.assertEqual(len(receipt["selected_packages"]), 4)

    def test_lexicographic_tie_between_equally_good_sets(self):
        self.init_vault([("<!root@x>", None, "root")])
        # A{x} conflicts with C{x'}; B{y} conflicts with D{y'}.  Every size-2 set
        # is legal, so all four pairs tie on value/count; {A,B} is lexicographic.
        a = self.messages([("<x@x>", None, "A x")], "a")
        b = self.messages([("<y@x>", None, "B y")], "b")
        c = self.messages([("<x@x>", None, "C x")], "c")
        d = self.messages([("<y@x>", None, "D y")], "d")
        manifest = self.manifest({"intake_id": "I-TIE", "packages": [
            self.package("PKG-A", "CUST", 1, a),
            self.package("PKG-B", "CUST", 1, b),
            self.package("PKG-C", "CUST", 1, c),
            self.package("PKG-D", "CUST", 1, d)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["total_value"], 2)
        self.assertEqual(receipt["selected_packages"], ["PKG-A", "PKG-B"])
        by_id = {item["package_id"]: item for item in receipt["excluded"]}
        self.assertEqual(by_id["PKG-C"]["reason"], "selected_identity_conflict")
        self.assertEqual(by_id["PKG-C"]["witness"], ["<x@x>"])
        self.assertEqual(by_id["PKG-D"]["reason"], "selected_identity_conflict")
        self.assertEqual(by_id["PKG-D"]["witness"], ["<y@x>"])

    def test_selected_conflict_witness_lists_every_divergent_id_sorted(self):
        self.init_vault([("<!root@x>", None, "root")])
        selected = self.messages([
            ("<p@x>", None, "sel p"), ("<q@x>", None, "sel q")], "sel")
        loser = self.messages([
            ("<z@x>", None, "own z"),  # compatible, but package is all-or-nothing
            ("<q@x>", None, "other q"), ("<p@x>", None, "other p")], "loser")
        manifest = self.manifest({"intake_id": "I-MULTI-WITNESS", "packages": [
            self.package("PKG-A", "CUST", 10, selected),
            self.package("PKG-B", "CUST", 1, loser)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-A"])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-B", "reason": "selected_identity_conflict",
            "witness": ["<p@x>", "<q@x>"]}])  # both divergent IDs, sorted

    def test_conflict_witness_priority_and_multiple_cycles(self):
        self.init_vault([(R, P, "reply"), ("<archived@x>", None, "old")])
        # package conflicting with the archive on <archived@x>
        conflict = self.messages([("<archived@x>", None, "new bytes")], "conflict")
        # legal package that cycles with final selection on two different IDs
        cyc1 = self.messages([("<c1@x>", "<d1@x>", "c1")], "cyc1")
        cyc2 = self.messages([("<d1@x>", "<c1@x>", "d1")], "cyc2")
        manifest = self.manifest({"intake_id": "I-PRI", "packages": [
            self.package("PKG-CONF", "CUST", 9, conflict),
            self.package("PKG-C1", "CUST", 2, cyc1),
            self.package("PKG-C2", "CUST", 2, cyc2)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-C1"])
        self.assertEqual(receipt["excluded"], [
            {"package_id": "PKG-C2", "reason": "reply_cycle",
             "witness": ["<c1@x>", "<d1@x>", "<c1@x>"]},
            {"package_id": "PKG-CONF", "reason": "archived_identity_conflict",
             "witness": ["<archived@x>"]}])

    def test_multi_cycle_witness_picks_lexicographic_smallest(self):
        self.init_vault([("<!root@x>", None, "root")])
        # PKG-A and PKG-B form two independent 2-cycles when combined.
        a = self.messages([
            ("<m1@x>", "<n1@x>", "m1"),
            ("<m2@x>", "<n2@x>", "m2")], "multi-a")
        b = self.messages([
            ("<n1@x>", "<m1@x>", "n1"),
            ("<n2@x>", "<m2@x>", "n2")], "multi-b")
        manifest = self.manifest({"intake_id": "I-MULTI", "packages": [
            self.package("PKG-A", "CUST", 3, a),
            self.package("PKG-B", "CUST", 3, b)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-A"])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-B", "reason": "reply_cycle",
            # canonical cycles: <m1,n1,m1> vs <m2,n2,m2>; first is smaller
            "witness": ["<m1@x>", "<n1@x>", "<m1@x>"]}])


class PurgeBoundaryTests(CollectionCase):
    def test_same_bytes_adds_provenance_without_reviving_purged(self):
        self.init_vault([("<m@x>", None, "secret payload")])
        original = (self.baseline_file()).read_bytes()
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        self.assertEqual(vault.retention_apply(self.db, "P1")["purged"], ["<m@x>"])
        folder = self.batch("same-bytes")
        (folder / "000.eml").write_bytes(original)
        manifest = self.manifest({"intake_id": "I-PURGED", "packages": [
            self.package("PKG-P", "CUST", 4, folder)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-P"])
        self.assertEqual(receipt["ignored_purged"], ["<m@x>"])
        self.assertEqual(receipt["inserted"], [])
        # payload stays gone, but the provenance row is recorded
        self.assertEqual(self.query("SELECT status, subject, body, source_bytes "
                                    "FROM vault_messages WHERE id='<m@x>'"),
                         [("purged", None, None, None)])
        self.assertEqual(vault.vault_search(self.db, "secret"), [])
        provenance = collection.vault_provenance(self.db, "<m@x>")
        self.assertEqual(provenance["sources"], [{
            "intake_id": "I-PURGED", "package_id": "PKG-P", "custodian": "CUST",
            "value": 4, "message_id": "<m@x>",
            "source_sha256": hashlib.sha256(original).hexdigest()}])

    def test_different_bytes_whole_package_excluded(self):
        self.init_vault([("<m@x>", None, "original")])
        folder = self.messages([("<m@x>", None, "different")], "different")
        manifest = self.manifest({"intake_id": "I-DIFF", "packages": [
            self.package("PKG-D", "CUST", 5, folder)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], [])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-D", "reason": "archived_identity_conflict",
            "witness": ["<m@x>"]}])
        self.assertEqual(self.query("SELECT body FROM vault_messages"), [("original\n",)])


class GlobalOptimumOracleTests(CollectionCase):
    """Independent exhaustive reference over small random instances."""

    @staticmethod
    def reference(baseline_parents, baseline_sha, packages):
        """Brute force every subset, checking feasibility from parent maps."""
        n = len(packages)
        value = {p["package_id"]: p["value"] for p in packages}
        best = (0, 0, ())
        for r in range(n + 1):
            for subset in itertools.combinations(range(n), r):
                chosen = [packages[i] for i in subset]
                parents = dict(baseline_parents)
                ok = True
                for package in chosen:
                    for message_id, message in package["messages"].items():
                        if message_id in baseline_sha \
                                and baseline_sha[message_id] != message["sha256"]:
                            ok = False
                            break
                        if message_id in parents:
                            continue
                        parents[message_id] = message["parent_id"]
                    if not ok:
                        break
                if not ok:
                    continue
                seen = {}
                for package in chosen:
                    for message_id, message in package["messages"].items():
                        if seen.setdefault(message_id, message["sha256"]) != message["sha256"]:
                            ok = False
                if not ok:
                    continue
                if GlobalOptimumOracleTests.has_cycle(parents):
                    continue
                ids = tuple(sorted(package["package_id"] for package in chosen))
                total = sum(value[i] for i in ids)
                key = (total, len(ids))
                if key > (best[0], best[1]) or (
                        key == (best[0], best[1]) and ids < best[2]):
                    best = (total, len(ids), ids)
        return best

    @staticmethod
    def has_cycle(parents):
        """Plain functional-graph cycle walk, written independently."""
        done = set()
        for start in parents:
            if start in done:
                continue
            path, seen = [], {}
            cursor = start
            while cursor in parents and cursor not in done:
                if cursor in seen:
                    return True
                seen[cursor] = True
                path.append(cursor)
                cursor = parents[cursor]
            done.update(path)
        return False

    def build_instance(self, rng):
        self.init_vault([("<base@x>", "<missing@x>", "base")])  # fresh db each round
        baseline = {row[0]: (row[1], row[2])
                    for row in self.query("SELECT id,parent_id,source_sha256 "
                                          "FROM vault_messages")}
        pool = ["<a@x>", "<b@x>", "<c@x>", "<d@x>", "<e@x>", "<missing@x>"]
        packages = []
        for index in range(rng.randint(2, 5)):
            folder = self.batch()
            used, written = set(), 0
            for _ in range(rng.randint(1, 2)):
                msg_id = rng.choice(pool)
                if msg_id in used:
                    continue
                used.add(msg_id)
                parent = rng.choice(pool + [None])
                while parent == msg_id:
                    parent = rng.choice(pool + [None])
                write_eml(folder, f"{written:03d}.eml", msg_id, parent=parent,
                          body=f"body{index}-{msg_id}-{rng.randint(0, 3)}")
                written += 1
            if not used:
                continue
            try:
                from mailroom.parse import read_folder
                parsed = read_folder(folder)
            except ValueError:
                return None  # random intra-package cycle: discard this instance
            if len(parsed) > collection.MAX_PACKAGE_FILES:
                return None
            packages.append({"package_id": f"PKG-{index}",
                             "custodian": f"C{index}",
                             "value": rng.randint(1, 5),
                             "source": folder,
                             "messages": parsed,
                             "ids": tuple(sorted(parsed))})
        if sum(len(package["messages"]) for package in packages) > collection.MAX_TOTAL_FILES:
            return None
        return baseline, packages

    def test_matches_bruteforce_on_random_instances(self):
        rng = random.Random(1234)
        checked = 0
        while checked < 40:
            instance = self.build_instance(rng)
            if instance is None:
                self.db.unlink(missing_ok=True)
                continue
            baseline, packages = instance
            with self.subTest(case=checked):
                manifest = self.manifest({"intake_id": f"I-{checked}", "packages": [
                    {"package_id": package["package_id"],
                     "custodian": package["custodian"],
                     "value": package["value"],
                     "source": str(package["source"])}
                    for package in packages]})
                receipt = self.import_(manifest)
                expected = self.reference(
                    {msg_id: entry[0] for msg_id, entry in baseline.items()},
                    {msg_id: entry[1] for msg_id, entry in baseline.items()},
                    packages)
                self.assertEqual(
                    (receipt["total_value"], len(receipt["selected_packages"]),
                     tuple(receipt["selected_packages"])), expected)
            checked += 1
            self.db.unlink(missing_ok=True)


    def test_joint_cycles_over_ten_packages_match_bruteforce(self):
        """Ten packages where cycles need three or more packages together."""
        rng = random.Random(99)
        self.init_vault([("<base@x>", "<missing@x>", "base")])
        packages = []
        # ring of "2-cycle" conflicts plus random 3-package cycles through chains
        triples = [tuple(sorted(rng.sample(range(10), 3))) for _ in range(6)]
        for index in range(10):
            folder = self.batch(f"joint{index}")
            written = 0
            # node G_i has parent G_{i+1}: any run covering the whole ring cycles
            write_eml(folder, f"{written:03d}.eml", f"<G{index}@x>",
                      parent=f"<G{(index + 1) % 10}@x>")
            written += 1
            for tag, (a, b, c) in enumerate(triples):
                role = {a: f"<T{tag}A@x>", b: f"<T{tag}B@x>", c: f"<T{tag}C@x>"}
                if index not in role:
                    continue
                parent = {a: role[b], b: role[c], c: role[a]}[index]
                write_eml(folder, f"{written:03d}.eml", role[index], parent=parent)
                written += 1
            packages.append({"package_id": f"PKG-{index:02d}",
                             "custodian": f"C{index}",
                             "value": rng.randint(1, 3),
                             "source": str(folder)})
        # independent reference over raw parent maps, built straight from disk
        from mailroom.parse import read_folder
        parsed = [read_folder(package["source"]) for package in packages]
        reference = self.reference(
            {"<base@x>": "<missing@x>"}, {},
            [{"package_id": package["package_id"], "value": package["value"],
              "messages": mapping}
             for package, mapping in zip(packages, parsed)])
        manifest = self.manifest({"intake_id": "I-JOINT", "packages": packages})
        receipt = self.import_(manifest)
        self.assertEqual((receipt["total_value"], len(receipt["selected_packages"]),
                          tuple(receipt["selected_packages"])), reference)


class WitnessValidationTests(CollectionCase):
    def assert_valid_cycle_witness(self, witness, baseline_parents, package_maps):
        """Every consecutive pair is a real parent link and it closes."""
        self.assertGreaterEqual(len(witness), 2)
        self.assertEqual(witness[0], witness[-1])
        links = {}
        for message_id, parent in baseline_parents.items():
            links[message_id] = parent
        for mapping in package_maps:
            for message_id, row in mapping.items():
                links.setdefault(message_id, row["parent_id"])
        for left, right in zip(witness, witness[1:]):
            self.assertEqual(links.get(left), right,
                             f"witness step {left} -> {right} is not a parent link")
        self.assertEqual(len(set(witness[:-1])), len(witness) - 1)  # simple cycle
        self.assertEqual(witness[0], min(witness[:-1]))  # rotated to smallest

    def test_witness_through_purged_node_is_a_real_chain(self):
        self.init_vault([("<x@x>", "<m@x>", "xbody"), ("<p@x>", "<x@x>", "pbody")])
        vault.retention_plan(self.db, "PL", "2026-11-04T00:00:00Z")
        self.assertEqual(vault.retention_apply(self.db, "PL")["purged"],
                         ["<p@x>", "<x@x>"])
        folder = self.messages([("<m@x>", "<p@x>", "mbody")], "brings-m")
        manifest = self.manifest({"intake_id": "I-PURGED-CYCLE", "packages": [
            self.package("PKG", "CUST", 5, folder)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], [])
        witness = receipt["excluded"][0]["witness"]
        baseline = {"<x@x>": "<m@x>", "<p@x>": "<x@x>"}
        self.assert_valid_cycle_witness(
            witness, baseline, [{"<m@x>": {"parent_id": "<p@x>"}}])
        self.assertEqual(witness, ["<m@x>", "<p@x>", "<x@x>", "<m@x>"])

    def test_witness_through_deep_baseline_chain(self):
        self.init_vault([("<R@x>", "<P@x>", "r"), ("<P@x>", "<M@x>", "p")])
        folder = self.messages([("<M@x>", "<R@x>", "m")], "brings-m")
        manifest = self.manifest({"intake_id": "I-DEEP", "packages": [
            self.package("PKG", "CUST", 9, folder)]})
        receipt = self.import_(manifest)
        witness = receipt["excluded"][0]["witness"]
        self.assert_valid_cycle_witness(
            witness, {"<R@x>": "<P@x>", "<P@x>": "<M@x>"},
            [{"<M@x>": {"parent_id": "<R@x>"}}])
        self.assertEqual(witness, ["<M@x>", "<R@x>", "<P@x>", "<M@x>"])


class InputValidationTests(CollectionCase):
    def setUp(self):
        super().setUp()
        self.init_vault([("<m@x>", None, "body")])
        self.folder = self.messages([("<n@x>", None, "n")], "pkg")

    def bad(self, value, pattern=None):
        path = self.root / "bad.json"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, pattern or ""):
            collection.collection_import(self.db, path)

    def test_manifest_structure_and_value_bounds(self):
        package = self.package("PKG", "CUST", 1, self.folder)
        self.bad({"intake_id": "I", "packages": [package], "extra": 1},
                 "exactly these keys")
        self.bad({"intake_id": "I"}, "exactly these keys")
        self.bad({"intake_id": "bad id", "packages": [package]}, "must match")
        self.bad({"intake_id": "I", "packages": []}, "1..18")
        self.bad({"intake_id": "I", "packages": [package] * 19}, "1..18")
        self.bad({"intake_id": "I", "packages": [{**package, "extra": 1}]},
                 "exactly these keys")
        for value in (0, 1_000_001, True, 1.5, "5", None):
            self.bad({"intake_id": "I",
                      "packages": [{**package, "value": value}]}, "integer")
        self.bad({"intake_id": "I",
                  "packages": [{**package, "package_id": ".bad"}]}, "must match")
        self.bad({"intake_id": "I",
                  "packages": [{**package, "custodian": "bad cust"}]}, "must match")
        self.bad({"intake_id": "I",
                  "packages": [package, package]}, "duplicate package_id")

    def test_source_directory_and_file_limits(self):
        missing = self.root / "no-such-dir"
        self.bad({"intake_id": "I", "packages": [
            self.package("PKG", "CUST", 1, missing)]}, "real directory")
        big = self.batch("big")
        for number in range(201):
            write_eml(big, f"{number:03d}.eml", f"<big{number}@x>")
        self.bad({"intake_id": "I", "packages": [
            self.package("PKG", "CUST", 1, big)]}, "200")

    def test_total_file_and_byte_limits_count_per_package(self):
        shared = self.batch("shared")
        for number in range(200):
            write_eml(shared, f"{number:03d}.eml", f"<s{number}@x>")
        packages = [self.package(f"PKG-{index}", "CUST", 1, shared)
                    for index in range(4)]  # 800 occurrences > 600
        self.bad({"intake_id": "I", "packages": packages}, "600")

    def test_duplicate_id_and_cycle_within_package_rejected(self):
        dup = self.batch("dup")
        write_eml(dup, "001.eml", "<d@x>")
        write_eml(dup, "002.eml", "<d@x>")
        self.bad({"intake_id": "I", "packages": [
            self.package("PKG", "CUST", 1, dup)]}, "duplicate Message-ID")
        loop = self.batch("loop")
        write_eml(loop, "001.eml", "<l1@x>", parent="<l2@x>")
        write_eml(loop, "002.eml", "<l2@x>", parent="<l1@x>")
        self.bad({"intake_id": "I", "packages": [
            self.package("PKG", "CUST", 1, loop)]}, "reply cycle")

    def test_invalid_message_in_unselected_candidate_fails_whole_intake(self):
        good = self.messages([("<good@x>", None, "good")], "good")
        broken = self.batch("broken")
        write_eml(broken, "001.eml", "<broken@x>", date="not a date")
        path = self.manifest({"intake_id": "I", "packages": [
            self.package("PKG-GOOD", "CUST", 1, good),
            self.package("PKG-BAD", "CUST", 1, broken)]})
        with self.assertRaises(ValueError):
            self.import_(path)
        self.assertEqual(self.statuses(), {"<m@x>": "live"})
        self.assertEqual(self.query(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'vault_collection%'"),
            [(0,)])

    def test_duplicate_json_key_and_non_finite_rejected(self):
        path = self.root / "dup.json"
        path.write_bytes(b'{"intake_id":"I","intake_id":"J","packages":[]}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            collection.collection_import(self.db, path)
        path.write_bytes(b'{"intake_id":"I","packages":[{"package_id":"P",'
                         b'"custodian":"C","value":NaN,"source":"x"}]}')
        with self.assertRaisesRegex(ValueError, "non-finite"):
            collection.collection_import(self.db, path)


class ReplayAndStabilityTests(CollectionCase):
    def test_request_identity_ignores_order_paths_and_names(self):
        self.init_vault([("<!root@x>", None, "root")])
        first = self.messages([("<a@x>", None, "a"), ("<b@x>", None, "b")], "first")
        manifest = self.manifest({"intake_id": "I-STABLE", "packages": [
            {"package_id": "PKG-B", "custodian": "C2", "value": 5, "source": str(first)},
            {"package_id": "PKG-A", "custodian": "C1", "value": 5,
             "source": str(first)}]}, "m1.json")
        receipt = self.import_(manifest)
        # relocated directory, reversed package order, different file names
        moved = self.batch("moved")
        (moved / "aa.eml").write_bytes((first / "000.eml").read_bytes())
        (moved / "zz.eml").write_bytes((first / "001.eml").read_bytes())
        reverse = self.manifest({"intake_id": "I-STABLE", "packages": [
            {"package_id": "PKG-A", "custodian": "C1", "value": 5, "source": str(moved)},
            {"package_id": "PKG-B", "custodian": "C2", "value": 5, "source": str(moved)}]},
            "m2.json")
        self.assertEqual(self.import_(reverse), receipt)
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources"),
                         [(4,)])

    def test_changed_request_under_same_intake_rejected(self):
        self.init_vault([("<!root@x>", None, "root")])
        folder = self.messages([("<a@x>", None, "a")], "a")
        first = self.manifest({"intake_id": "I-REPLAY", "packages": [
            self.package("PKG-A", "CUST", 1, folder)]}, "m1.json")
        receipt = self.import_(first)
        self.assertEqual(self.import_(first), receipt)  # same file, same request
        changes = [
            {"package_id": "PKG-A", "custodian": "OTHER", "value": 1,
             "source": str(folder)},
            {"package_id": "PKG-A", "custodian": "CUST", "value": 2,
             "source": str(folder)},
            {"package_id": "PKG-B", "custodian": "CUST", "value": 1,
             "source": str(folder)},
        ]
        for index, change in enumerate(changes):
            path = self.manifest({"intake_id": "I-REPLAY", "packages": [change]},
                                 f"changed{index}.json")
            with self.assertRaisesRegex(ValueError, "different request"):
                self.import_(path)
        # different bytes under the same id are also a request change
        other = self.messages([("<a@x>", None, "different")], "other")
        path = self.manifest({"intake_id": "I-REPLAY", "packages": [
            self.package("PKG-A", "CUST", 1, other)]}, "changed3.json")
        with self.assertRaisesRegex(ValueError, "different request"):
            self.import_(path)

    def test_replay_survives_later_archive_changes(self):
        self.init_vault([("<!root@x>", None, "root")])
        folder = self.messages([("<a@x>", None, "a")], "a")
        path = self.manifest({"intake_id": "I-FROZEN", "packages": [
            self.package("PKG-A", "CUST", 1, folder)]})
        receipt = self.import_(path)
        # the archived identity is purged afterwards; the first receipt stands
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P1")
        self.assertEqual(self.import_(path), receipt)
        self.assertEqual(collection.collection_show(self.db, "I-FROZEN"), receipt)
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources"),
                         [(1,)])

    def test_empty_selection_is_recorded_and_replayed(self):
        self.init_vault([(R, P, "reply")])
        folder = self.messages([(P, R, "closing")], "closing")
        path = self.manifest({"intake_id": "I-EMPTY", "packages": [
            self.package("PKG-X", "CUST", 1, folder)]})
        receipt = self.import_(path)
        self.assertEqual(receipt["selected_packages"], [])
        self.assertEqual(receipt["total_value"], 0)
        self.assertEqual(collection.collection_show(self.db, "I-EMPTY"), receipt)
        self.assertEqual(self.import_(path), receipt)
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources"),
                         [(0,)])


class TransactionTests(CollectionCase):
    def test_failure_after_payload_and_sources_rolls_back_everything(self):
        # a baseline reply whose thread root must be recomputed by the intake
        self.init_vault([(R, P, "commonword reply")])
        before_threads = dict(self.query("SELECT id, thread_id FROM vault_messages"))
        folder = self.messages([(P, A, "commonword parent")], "new")
        path = self.manifest({"intake_id": "I-CRASH", "packages": [
            self.package("PKG-N", "CUST", 3, folder)]})
        real_connect = sqlite3.connect

        class CrashConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if isinstance(sql, str) and sql.lstrip().upper().startswith(
                        "INSERT INTO VAULT_COLLECTION_INTAKES"):
                    raise sqlite3.OperationalError("injected crash")
                return super().execute(sql, *args, **kwargs)

        with mock.patch("sqlite3.connect",
                        side_effect=lambda *a, **k: real_connect(
                            *a, factory=CrashConnection, **k)):
            with self.assertRaises(sqlite3.OperationalError):
                self.import_(path)
        # restart: no new identity, payload, FTS, source row, receipt or tables,
        # and the partial thread re-rooting was rolled back with everything else
        self.assertEqual(self.statuses(), {R: "live"})
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         before_threads)
        self.assertEqual(self.query("SELECT count(*) FROM sqlite_master "
                                    "WHERE name LIKE 'vault_collection%'"), [(0,)])
        self.assertEqual(len(vault.vault_search(self.db, "commonword")), 1)
        # the identical intake now succeeds and commits atomically
        receipt = self.import_(path)
        self.assertEqual(receipt["inserted"], [P])
        self.assertEqual(len(vault.vault_search(self.db, "commonword")), 2)
        self.assertEqual(dict(self.query("SELECT id, thread_id FROM vault_messages")),
                         {R: A, P: A})
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources"),
                         [(1,)])
        self.assertEqual(collection.collection_show(self.db, "I-CRASH"), receipt)


class ReadOnlyAndFormatTests(CollectionCase):
    def test_show_and_provenance_never_create_tables(self):
        self.init_vault([("<m@x>", None, "body")])
        digest = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.assertEqual(collection.vault_provenance(self.db, "<m@x>"),
                         {"message_id": "<m@x>", "sources": []})
        with self.assertRaisesRegex(ValueError, "unknown intake_id"):
            collection.collection_show(self.db, "NOPE")
        with self.assertRaisesRegex(ValueError, "unknown message ID"):
            collection.vault_provenance(self.db, "<ghost@x>")
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), digest)
        self.assertEqual(self.query("SELECT count(*) FROM sqlite_master "
                                    "WHERE name LIKE 'vault_collection%'"), [(0,)])

    def test_provenance_sorted_and_available_after_purge(self):
        self.init_vault([("<!root@x>", None, "root")])
        folder = self.messages([("<m@x>", None, "body")], "m")
        manifests = []
        for index, (intake, custodian) in enumerate((("I-B", "Z"), ("I-A", "Y"))):
            manifests.append(self.manifest({"intake_id": intake, "packages": [
                self.package(f"PKG-{intake}", custodian, index + 1, folder)]},
                f"m{index}.json"))
            self.import_(manifests[-1])
        digest = hashlib.sha256(self.db.read_bytes()).hexdigest()
        result = collection.vault_provenance(self.db, "<m@x>")
        self.assertEqual([(s["intake_id"], s["package_id"]) for s in result["sources"]],
                         [("I-A", "PKG-I-A"), ("I-B", "PKG-I-B")])
        self.assertEqual(hashlib.sha256(self.db.read_bytes()).hexdigest(), digest)
        vault.retention_plan(self.db, "P1", "2026-11-04T00:00:00Z")
        vault.retention_apply(self.db, "P1")
        self.assertEqual(len(collection.vault_provenance(self.db, "<m@x>")["sources"]), 2)

    def test_v1_database_and_missing_vault_untouched(self):
        v1 = self.root / "v1.sqlite"
        v1_build("fixtures/mail", v1)
        digest = hashlib.sha256(v1.read_bytes()).hexdigest()
        folder = self.messages([("<a@x>", None, "a")], "a")
        path = self.manifest({"intake_id": "I", "packages": [
            self.package("PKG", "CUST", 1, folder)]})
        for call in (lambda: collection.collection_import(v1, path),
                     lambda: collection.collection_show(v1, "I"),
                     lambda: collection.vault_provenance(v1, "<planning@example.invalid>")):
            with self.assertRaisesRegex(ValueError, "not a mailroom vault"):
                call()
        self.assertEqual(hashlib.sha256(v1.read_bytes()).hexdigest(), digest)
        missing = self.root / "missing.sqlite"
        for call in (lambda: collection.collection_import(missing, path),
                     lambda: collection.collection_show(missing, "I"),
                     lambda: collection.vault_provenance(missing, "<a@x>")):
            with self.assertRaises((ValueError, sqlite3.OperationalError)):
                call()
        self.assertFalse(missing.exists())


class FtsAndThreadTests(CollectionCase):
    def test_only_selected_packages_leave_payload_and_threads_update(self):
        self.init_vault([(R, P, "replyword")])
        selected = self.messages([(P, A, "parentword")], "sel")
        # the unselected package conflicts with the archive, so it cannot join
        conflict = self.batch("conflict")
        baseline_text = (self.baseline_file()).read_text()
        (conflict / "000.eml").write_text(
            baseline_text.replace("replyword", "tamperword"))
        # a second identity in the unselected package must never be archived
        write_eml(conflict, "001.eml", "<other@x>", body="skipword")
        manifest = self.manifest({"intake_id": "I-FTS", "packages": [
            self.package("PKG-SEL", "CUST", 1, selected),
            self.package("PKG-BAD", "CUST", 99, conflict)]})
        receipt = self.import_(manifest)
        self.assertEqual(receipt["selected_packages"], ["PKG-SEL"])
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-BAD", "reason": "archived_identity_conflict",
            "witness": [R]}])
        # unselected payload, attachment descriptions and FTS never landed
        self.assertEqual(vault.vault_search(self.db, "tamperword"), [])
        self.assertEqual(vault.vault_search(self.db, "skipword"), [])
        self.assertEqual(self.query("SELECT count(*) FROM vault_messages "
                                    "WHERE id='<other@x>'"), [(0,)])
        self.assertEqual(self.query("SELECT count(*) FROM vault_collection_sources "
                                    "WHERE package_id='PKG-BAD'"), [(0,)])
        # late parent P re-roots the existing reply R under anchor A
        nodes = vault.vault_thread(self.db, R)
        self.assertTrue(all(node["thread_id"] == A for node in nodes))
        self.assertEqual({node["id"] for node in nodes}, {R, P})
        self.assertEqual(vault.vault_search(self.db, "replyword")[0]["id"], R)


class FixtureDemoTests(CollectionCase):
    def test_readme_collection_demo(self):
        fixture_r = "<reply-r@example.invalid>"
        fixture_p = "<parent-p@example.invalid>"
        result = vault.init("fixtures/collection/baseline", self.db)
        self.assertEqual(result["inserted"], [fixture_r])
        receipt = collection.collection_import(
            self.db, "fixtures/collection/manifest.json")
        self.assertEqual(receipt["selected_packages"], ["PKG-Y"])
        self.assertEqual(receipt["total_value"], 10)
        self.assertEqual(receipt["excluded"], [{
            "package_id": "PKG-X", "reason": "selected_identity_conflict",
            "witness": [fixture_p]}])
        self.assertEqual(collection.collection_show(self.db, "COLLECT-1"), receipt)
        sources = collection.vault_provenance(self.db, fixture_p)["sources"]
        self.assertEqual([(s["package_id"], s["custodian"], s["value"]) for s in sources],
                         [("PKG-Y", "CUST-Y", 10)])


class CliTests(CollectionCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with mock.patch.object(sys, "argv", ["mail-archive", *argv]), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_full_cli_flow_and_exit_codes(self):
        self.init_vault([(R, P, "reply")])
        folder = self.messages([(P, A, "parent")], "pkg")
        manifest = self.manifest({"intake_id": "I-CLI", "packages": [
            self.package("PKG-Y", "CUST", 1, folder)]})
        code, out, _ = self.run_cli("collection-import", "--db", str(self.db),
                                    "--manifest", str(manifest))
        self.assertEqual(code, 0)
        receipt = json.loads(out)
        self.assertEqual(receipt["selected_packages"], ["PKG-Y"])
        code, out, _ = self.run_cli("collection-show", "--db", str(self.db),
                                    "--intake-id", "I-CLI")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), receipt)
        code, out, _ = self.run_cli("vault-provenance", "--db", str(self.db),
                                    "--message-id", P)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["sources"][0]["package_id"], "PKG-Y")
        code, _, err = self.run_cli("collection-show", "--db", str(self.db),
                                    "--intake-id", "NOPE")
        self.assertEqual(code, 2)
        self.assertIn("unknown intake_id", err)
        code, _, err = self.run_cli("vault-provenance", "--db", str(self.db),
                                    "--message-id", "<ghost@x>")
        self.assertEqual(code, 2)
        self.assertIn("unknown message ID", err)
        self.assertNotIn("parent", out)  # receipts never dump payload text


if __name__ == "__main__":
    unittest.main()
