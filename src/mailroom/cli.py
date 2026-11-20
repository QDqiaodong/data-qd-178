import argparse
import json
import sqlite3
import sys
from . import vault, review
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
        else:
            result = vault.vault_thread(args.db, args.message_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except vault.HoldBlocked as exc:
        detail = {"error": "held", "blocked": exc.blocked}
        sys.stderr.write(json.dumps(detail, ensure_ascii=False, indent=2) + "\n")
        p.exit(2)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, OverflowError) as exc:
        p.exit(2, f"mail-archive: {exc}\n")


if __name__ == "__main__":
    main()
