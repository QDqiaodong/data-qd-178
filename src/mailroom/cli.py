import argparse
import json
import sqlite3
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
    args = p.parse_args()
    try:
        if args.command == "import":
            result = build(args.source, args.db)
        elif args.command == "search":
            result = search(args.db, args.query)
        else:
            result = thread(args.db, args.message_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, OverflowError) as exc:
        p.exit(2, f"mail-archive: {exc}\n")


if __name__ == "__main__":
    main()
