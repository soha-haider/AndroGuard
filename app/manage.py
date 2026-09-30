"""Create or reset the superadmin:  python -m app.manage create-superadmin you@example.com
The password comes from the ANDROGUARD_PASSWORD environment variable, or an interactive prompt."""
import getpass
import os
import sys
from fastapi import HTTPException
from app import auth
from app.database import Session, User

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "create-superadmin":
        sys.exit(__doc__)
    password = os.environ.get("ANDROGUARD_PASSWORD") or getpass.getpass("Password: ")
    try:
        email = auth.validate(sys.argv[2], password)
    except HTTPException as e:
        sys.exit(e.detail)
    with Session() as s:
        user = s.query(User).filter_by(email=email).first() or User(email=email, name="Superadmin")
        user.password_hash, user.role, user.status, user.scan_limit = auth.hash_password(password), "superadmin", "active", None
        s.add(user)
        s.commit()
    auth.end_sessions(user.id)  # a reset password signs the old sessions out
    print(f"Superadmin ready: {email}")
