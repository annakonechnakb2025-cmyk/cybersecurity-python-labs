import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

PASSWORD_ITERATIONS = 100_000


class User:
    def __init__(self, username, email, role, active=True):
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = None
        self.__password_salt = None

    def set_password(self, password):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )

    def check_password(self, password):
        if self.__password_hash is None or self.__password_salt is None:
            return False

        password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )

        return hmac.compare_digest(self.__password_hash, password_hash)

    def deactivate(self):
        self.active = False

    def __str__(self):
        return (
            f"User(username={self.username}, "
            f"email={self.email}, role={self.role}, active={self.active})"
        )

    @property
    def email(self):
        return self.__email

    @email.setter
    def email(self, value):
        pattern = r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

        if not re.match(pattern, value):
            raise ValueError("Invalid email format")

        self.__email = value


class Admin(User):
    def __init__(self, username, email, role="admin", active=True):
        super().__init__(username, email, role, active)
        self.permissions = set()

    def grant_permission(self, permission):
        self.permissions.add(permission)

    def revoke_permission(self, permission):
        self.permissions.discard(permission)

    def has_permission(self, permission):
        return permission in self.permissions

    def __str__(self):
        return (
            f"Admin(username={self.username}, "
            f"email={self.email}, permissions={self.permissions})"
        )


class Session:
    def __init__(self, ip):
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = self.login_time

    def touch(self):
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec):
        if timeout_sec <= 0:
            raise ValueError("Timeout must be positive")

        now = datetime.now(timezone.utc)
        return now - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    action: str
    username: str
    timestamp: datetime


class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, action, username):
        record = AuditRecord(
            action=action,
            username=username,
            timestamp=datetime.now(timezone.utc),
        )
        self.records.append(record)

    def show_all(self):
        for record in self.records:
            print(record)


class UserAccount:
    SESSION_TIMEOUT_SEC = 900

    def __init__(self, user):
        self.user = user
        self.session = None
        self.audit_log = AuditLog()

    def login(self, password, ip):
        if not self.user.active:
            self.audit_log.add_log("login_failure", self.user.username)
            return False

        if not self.user.check_password(password):
            self.audit_log.add_log("login_failure", self.user.username)
            return False

        self.session = Session(ip)
        self.audit_log.add_log("login_success", self.user.username)
        return True

    def is_authenticated(self):
        if self.session is None:
            return False

        return self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self):
        if self.session is not None:
            self.audit_log.add_log("logout", self.user.username)
            self.session = None

    def __getitem__(self, key):
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log

        raise KeyError(key)

    def __setitem__(self, key, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("user must be User")
            self.user = value
            return

        if key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("session must be Session or None")
            self.session = value
            return

        if key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("audit_log must be AuditLog")
            self.audit_log = value
            return

        raise KeyError(key)
