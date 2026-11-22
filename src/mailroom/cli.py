import argparse
import json
import sqlite3
import sys
import zlib
from . import vault, review, collection, recovery, mbox, investigate
from .archive import build, search, thread


def main():
    p = argparse.ArgumentParser(description="Offline MIME evidence archive")
    commands = p.add_subparsers(dest="command", required=True)
    imp = commands.add_parser("import")
    imp.add_argument("--source", required=True)
    imp.add_argument("--db", required=True)
    find = commands.add_parser("search")
    find.add_argument("--db", required=True)
    find.add_argument("--query", required=True)
    chain = commands.add_parser("thread")
    chain.add_argument("--db", required=True)
    chain.add_argument("--message-id", required=True)
    vinit = commands.add_parser("vault-init")
    vinit.add_argument("--source", required=True)
    vinit.add_argument("--db", required=True)
    vingest = commands.add_parser("vault-ingest")
    vingest.add_argument("--source", required=True)
    vingest.add_argument("--db", required=True)
    hadd = commands.add_parser("hold-add")
    hadd.add_argument("--db", required=True)
    hadd.add_argument("--hold-id", required=True)
    hadd.add_argument("--anchor", required=True)
    hrel = commands.add_parser("hold-release")
    hrel.add_argument("--db", required=True)
    hrel.add_argument("--hold-id", required=True)
    rplan = commands.add_parser("retention-plan")
    rplan.add_argument("--db", required=True)
    rplan.add_argument("--plan-id", required=True)
    rplan.add_argument("--before", required=True)
    rshow = commands.add_parser("retention-show")
    rshow.add_argument("--db", required=True)
    rshow.add_argument("--plan-id", required=True)
    rapply = commands.add_parser("retention-apply")
    rapply.add_argument("--db", required=True)
    rapply.add_argument("--plan-id", required=True)
    vfind = commands.add_parser("vault-search")
    vfind.add_argument("--db", required=True)
    vfind.add_argument("--query", required=True)
    vchain = commands.add_parser("vault-thread")
    vchain.add_argument("--db", required=True)
    vchain.add_argument("--message-id", required=True)
    ropen = commands.add_parser("review-open")
    ropen.add_argument("--db", required=True)
    ropen.add_argument("--spec", required=True)
    rexport = commands.add_parser("review-export")
    rexport.add_argument("--db", required=True)
    rexport.add_argument("--review-id", required=True)
    rexport.add_argument("--output", required=True)
    rreturn = commands.add_parser("review-return")
    rreturn.add_argument("--db", required=True)
    rreturn.add_argument("--review-id", required=True)
    rreturn.add_argument("--package", required=True)
    rreturn.add_argument("--feedback", required=True)
    rnotes = commands.add_parser("review-notes")
    rnotes.add_argument("--db", required=True)
    rnotes.add_argument("--message-id", required=True)
    cimport = commands.add_parser("collection-import")
    cimport.add_argument("--db", required=True)
    cimport.add_argument("--manifest", required=True)
    cshow = commands.add_parser("collection-show")
    cshow.add_argument("--db", required=True)
    cshow.add_argument("--intake-id", required=True)
    vprov = commands.add_parser("vault-provenance")
    vprov.add_argument("--db", required=True)
    vprov.add_argument("--message-id", required=True)
    renable = commands.add_parser("recovery-enable")
    renable.add_argument("--db", required=True)
    rinfo = commands.add_parser("recovery-info")
    rinfo.add_argument("--db", required=True)
    rcheck = commands.add_parser("recovery-checkpoint")
    rcheck.add_argument("--db", required=True)
    rcheck.add_argument("--output", required=True)
    rauth = commands.add_parser("recovery-authority")
    rauth.add_argument("--db", required=True)
    rauth.add_argument("--output", required=True)
    rrestore = commands.add_parser("recovery-restore")
    rrestore.add_argument("--checkpoint", required=True)
    rrestore.add_argument("--checkpoint-sha256", required=True)
    rrestore.add_argument("--authority", required=True)
    rrestore.add_argument("--authority-sha256", required=True)
    rrestore.add_argument("--min-revision", required=True)
    rrestore.add_argument("--db", required=True)
    mscan = commands.add_parser("mbox-scan")
    mscan.add_argument("--db", required=True)
    mscan.add_argument("--source-id", required=True)
    mscan.add_argument("--source", required=True)
    mscan.add_argument("--limit", type=int, default=mbox.DEFAULT_LIMIT)
    mscan.add_argument("--seal", action="store_true")
    mshow = commands.add_parser("mbox-show")
    mshow.add_argument("--db", required=True)
    mshow.add_argument("--source-id", required=True)
    mresolve = commands.add_parser("mbox-resolve")
    mresolve.add_argument("--db", required=True)
    mresolve.add_argument("--decision", required=True)
    mcert = commands.add_parser("mbox-certify")
    mcert.add_argument("--db", required=True)
    mcert.add_argument("--source-id", required=True)
    ainv = commands.add_parser("attachment-investigate")
    ainv.add_argument("--db", required=True)
    ainv.add_argument("--spec", required=True)
    ainv.add_argument("--output", required=True)
    adel = commands.add_parser("attachment-deliver")
    adel.add_argument("--db", required=True)
    adel.add_argument("--report", required=True)
    adel.add_argument("--report-sha256", required=True)
    adel.add_argument("--output", required=True)
    args = p.parse_args()
    try:
        if args.command == "import":
            result = build(args.source, args.db)
        elif args.command == "search":
            result = search(args.db, args.query)
        elif args.command == "thread":
            result = thread(args.db, args.message_id)
        elif args.command == "vault-init":
            result = vault.init(args.source, args.db)
        elif args.command == "vault-ingest":
            result = vault.ingest(args.source, args.db)
        elif args.command == "hold-add":
            result = vault.hold_add(args.db, args.hold_id, args.anchor)
        elif args.command == "hold-release":
            result = vault.hold_release(args.db, args.hold_id)
        elif args.command == "retention-plan":
            result = vault.retention_plan(args.db, args.plan_id, args.before)
        elif args.command == "retention-show":
            result = vault.retention_show(args.db, args.plan_id)
        elif args.command == "retention-apply":
            result = vault.retention_apply(args.db, args.plan_id)
        elif args.command == "vault-search":
            result = vault.vault_search(args.db, args.query)
        elif args.command == "review-open":
            result = review.review_open(args.db, args.spec)
        elif args.command == "review-export":
            result = review.review_export(args.db, args.review_id, args.output)
        elif args.command == "review-return":
            result = review.review_return(
                args.db, args.review_id, args.package, args.feedback)
        elif args.command == "review-notes":
            result = review.review_notes(args.db, args.message_id)
        elif args.command == "collection-import":
            result = collection.collection_import(args.db, args.manifest)
        elif args.command == "collection-show":
            result = collection.collection_show(args.db, args.intake_id)
        elif args.command == "vault-provenance":
            result = collection.vault_provenance(args.db, args.message_id)
        elif args.command == "recovery-enable":
            result = recovery.enable(args.db)
        elif args.command == "recovery-info":
            result = recovery.info(args.db)
        elif args.command == "recovery-checkpoint":
            result = recovery.checkpoint(args.db, args.output)
        elif args.command == "recovery-authority":
            result = recovery.authority(args.db, args.output)
        elif args.command == "recovery-restore":
            result = recovery.restore(
                args.checkpoint, args.checkpoint_sha256, args.authority,
                args.authority_sha256, recovery.parse_revision(args.min_revision),
                args.db)
        elif args.command == "mbox-scan":
            result = mbox.mbox_scan(args.db, args.source_id, args.source,
                                    limit=args.limit, seal=args.seal)
        elif args.command == "mbox-show":
            result = mbox.mbox_show(args.db, args.source_id)
        elif args.command == "mbox-resolve":
            result = mbox.mbox_resolve(args.db, args.decision)
        elif args.command == "mbox-certify":
            result = mbox.mbox_certify(args.db, args.source_id)
        elif args.command == "attachment-investigate":
            result = investigate.investigate(args.db, args.spec, args.output)
        elif args.command == "attachment-deliver":
            result = investigate.deliver(args.db, args.report,
                                         args.report_sha256, args.output)
        else:
            result = vault.vault_thread(args.db, args.message_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except vault.HoldBlocked as exc:
        detail = {"error": "held", "blocked": exc.blocked}
        sys.stderr.write(json.dumps(detail, ensure_ascii=False, indent=2) + "\n")
        p.exit(2)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error,
            OverflowError, zlib.error) as exc:
        p.exit(2, f"mail-archive: {exc}\n")


if __name__ == "__main__":
    main()
