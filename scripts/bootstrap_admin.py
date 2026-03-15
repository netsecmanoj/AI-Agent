"""Bootstrap the first local admin user."""

from __future__ import annotations

import argparse
import os
import sys

from backend.app.core.database import SessionLocal, init_db
from backend.app.services.auth_service import AuthService


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments for admin bootstrap."""
    parser = argparse.ArgumentParser(description="Create the first admin user.")
    parser.add_argument("--username", default=os.getenv("BOOTSTRAP_ADMIN_USERNAME"))
    parser.add_argument("--password", default=os.getenv("BOOTSTRAP_ADMIN_PASSWORD"))
    return parser.parse_args()


def main() -> int:
    """Create a local admin user from CLI args or environment variables."""
    args = parse_args()
    if not args.username or not args.password:
        print("Username and password are required via args or BOOTSTRAP_ADMIN_* env vars.", file=sys.stderr)
        return 1

    init_db()
    with SessionLocal() as db:
        service = AuthService(db)
        try:
            user = service.create_admin_user(args.username, args.password)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    print(f"Created admin user: {user.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
