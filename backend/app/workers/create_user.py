"""Interactive account provisioning: python -m app.workers.create_user NAME ROLE."""
import argparse
import asyncio
import getpass
from uuid import uuid4

from sqlalchemy import select

from app.core.auth import audit, password_hash
from app.core.database import async_session_factory
from app.models.identity import SOCUser


async def create(username, role, password):
    async with async_session_factory() as db:
        user = await db.scalar(select(SOCUser).where(SOCUser.username == username.casefold()))
        if user is None:
            user = SOCUser(id=uuid4(), username=username.casefold(), password_hash=password_hash(password), role=role, active=True)
            db.add(user)
        else:
            user.password_hash, user.role, user.active = password_hash(password), role, True
        audit(db, "account.provision", username.casefold(), details={"role": role})
        await db.commit()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument("role", choices=["viewer", "analyst", "admin"])
    args = parser.parse_args()
    if not args.username.strip() or len(args.username) > 128:
        parser.error("Username must be between 1 and 128 characters")
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Repeat password: ")
    if len(password) < 12 or password != confirmation:
        parser.error("Matching passwords of at least 12 characters are required")
    asyncio.run(create(args.username.strip(), args.role, password))
    print(f"Provisioned {args.role} account: {args.username}")


if __name__ == "__main__":
    main()
