"""Gray-Box Authentication and Account Role Manager.

Manages dedicated test identities (User A, User B, Privileged, Admin, Anonymous)
for multi-role assessments such as IDOR, Privilege Escalation, and Session Replay.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from graybox.models import AccountRole


@dataclass
class TestAccount:
    __test__ = False
    role: AccountRole
    username: str
    password: str = ""
    token: str = ""
    bearer_token: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    owned_resources: list[str] = field(default_factory=list)
    is_active: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        if self.bearer_token and not self.token:
            self.token = self.bearer_token
        elif self.token and not self.bearer_token:
            self.bearer_token = self.token

    def safe_dict(self) -> dict[str, Any]:
        """Return safe representation with credentials redacted."""
        return {
            "role": self.role.value if hasattr(self.role, "value") else str(self.role),
            "username": self.username,
            "password": "[REDACTED]" if self.password else "",
            "bearer_token": "[REDACTED]" if self.token else "",
            "has_password": bool(self.password),
            "has_token": bool(self.token),
            "cookie_names": list(self.cookies.keys()),
            "header_names": list(self.headers.keys()),
            "owned_resources": self.owned_resources,
            "is_active": self.is_active,
            "notes": self.notes,
        }

    def auth_headers(self) -> dict[str, str]:
        """Return authorization headers for HTTP requests."""
        hdrs = dict(self.headers)
        if self.token and "Authorization" not in hdrs and "authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {self.token}"
        return hdrs


class GrayBoxAccountManager:
    """Manages test identities and roles for Gray-Box assessments."""

    def __init__(self) -> None:
        self._accounts: dict[AccountRole, TestAccount] = {
            AccountRole.ANONYMOUS: TestAccount(
                role=AccountRole.ANONYMOUS,
                username="anonymous",
                notes="Unauthenticated visitor",
            )
        }

    def set_account(
        self,
        role: AccountRole | str,
        username: str,
        password: str = "",
        token: str = "",
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        owned_resources: list[str] | None = None,
        notes: str = "",
    ) -> TestAccount:
        if isinstance(role, str):
            role = AccountRole(role)

        account = TestAccount(
            role=role,
            username=username.strip(),
            password=password,
            token=token.strip(),
            cookies=cookies or {},
            headers=headers or {},
            owned_resources=owned_resources or [],
            notes=notes,
        )
        self._accounts[role] = account
        return account

    def get_account(self, role: AccountRole | str) -> TestAccount | None:
        if isinstance(role, str):
            role = AccountRole(role)
        return self._accounts.get(role)

    def has_role(self, role: AccountRole | str) -> bool:
        acc = self.get_account(role)
        if not acc or not acc.is_active:
            return False
        if acc.role == AccountRole.ANONYMOUS:
            return True
        return bool(acc.username or acc.token or acc.cookies)

    def satisfies_roles(self, required_roles: list[AccountRole]) -> tuple[bool, list[str]]:
        """Verify whether the configured accounts satisfy the required roles."""
        missing = []
        for role in required_roles:
            if not self.has_role(role):
                missing.append(role.value if hasattr(role, "value") else str(role))
        return (len(missing) == 0, missing)

    def add_account(self, account: TestAccount) -> None:
        """Register or replace an account for its role."""
        self._accounts[account.role] = account

    def get_account_for_role(self, role: AccountRole | str) -> TestAccount | None:
        """Alias for get_account."""
        return self.get_account(role)

    def get_redacted_accounts(self) -> list[dict[str, Any]]:
        """Return list of all registered accounts with secrets redacted."""
        return [acc.safe_dict() for acc in self._accounts.values()]

    def summary(self) -> dict[str, Any]:
        return {
            role.value if hasattr(role, "value") else str(role): acc.safe_dict()
            for role, acc in self._accounts.items()
        }
