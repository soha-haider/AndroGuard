"""Accounts: scrypt password hashes, server-side sessions in an HttpOnly cookie, a device cookie for the free trial,
roles (user < admin < superadmin) and a failed-login limit."""
import hashlib
import hmac
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import timedelta
from fastapi import HTTPException, Request, Response
from app.database import AuthSession, Session, User, now

SESSION_COOKIE, DEVICE_COOKIE = "ag_session", "ag_device"
SESSION_DAYS = 7
EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}")
_failures: dict[str, deque] = defaultdict(deque)  # ponytail: per-process; move to Redis with several workers


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, salt, digest = stored.split("$")
    return hmac.compare_digest(hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex(),
                               digest)


def validate(email: str, password: str) -> str:
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL.fullmatch(email):
        raise HTTPException(422, "Enter a valid email address")
    if not 8 <= len(password) <= 128:
        raise HTTPException(422, "Use a password of 8 to 128 characters")
    return email


def _cookie(response: Response, request: Request, name: str, value: str, days: int):
    response.set_cookie(name, value, max_age=days * 86400, httponly=True, samesite="lax",
                        secure=request.url.scheme == "https")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(request: Request, response: Response, user_id: int):
    token = secrets.token_urlsafe(32)
    with Session() as s:
        s.add(AuthSession(token_hash=_token_hash(token), user_id=user_id, expires_at=now() + timedelta(days=SESSION_DAYS)))
        s.query(User).filter_by(id=user_id).update({"last_login_at": now()})
        s.commit()
    _cookie(response, request, SESSION_COOKIE, token, SESSION_DAYS)


def end_sessions(user_id: int):
    with Session() as s:
        s.query(AuthSession).filter_by(user_id=user_id).delete()
        s.commit()


def logout(request: Request, response: Response):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with Session() as s:
            s.query(AuthSession).filter_by(token_hash=_token_hash(token)).delete()
            s.commit()
    response.delete_cookie(SESSION_COOKIE)


def current_user(request: Request) -> User | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with Session() as s:
        user = s.query(User).join(AuthSession, AuthSession.user_id == User.id).filter(
            AuthSession.token_hash == _token_hash(token), AuthSession.expires_at > now()).first()
    return user if user and user.status == "active" else None


def device_id(request: Request, response: Response) -> str:
    device = request.cookies.get(DEVICE_COOKIE, "")
    if not re.fullmatch(r"[\w-]{16,64}", device):
        device = secrets.token_urlsafe(24)
        _cookie(response, request, DEVICE_COOKIE, device, 365)
    return device


def require_admin(request: Request) -> User:
    user = current_user(request)
    if user is None:
        raise HTTPException(401, "Sign in first")
    if user.role not in ("admin", "superadmin"):
        raise HTTPException(403, "Admins only")
    return user


def check_login_rate(key: str):
    attempts = _failures[key]
    while attempts and attempts[0] < time.monotonic() - 900:
        attempts.popleft()
    if len(attempts) >= 5:
        raise HTTPException(429, "Too many failed attempts. Try again in 15 minutes.")


def record_failure(key: str):
    _failures[key].append(time.monotonic())
