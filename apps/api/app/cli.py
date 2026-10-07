"""Admin CLI.

Usage: python -m app.cli create-user --email admin@example.com --name "Admin" --role ADMIN
The password is read from a prompt, never from argv, so it does not land in shell history.
"""

import argparse
import getpass
import sys

from app.core.enums import Role
from app.db.session import SessionLocal
from app.services.users import create_user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    cu = sub.add_parser("create-user", help="Create a local user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--name", required=True)
    cu.add_argument("--role", choices=[r.value for r in Role], default=Role.VIEWER.value)
    args = parser.parse_args(argv)

    if args.command == "create-user":
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm password: "):
            print("Passwords do not match", file=sys.stderr)
            return 1
        with SessionLocal() as db:
            try:
                user = create_user(db, args.email, args.name, password, Role(args.role))
                db.commit()
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1
        print(f"Created {user.role.value} user {user.email}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
