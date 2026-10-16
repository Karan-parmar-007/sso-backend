from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

ADMIN_ROLES = frozenset({"owner", "super_admin"})


class SsoIdentity(BaseModel):
    """The signed-in SSO user, from a verified access token (or live /me)."""

    model_config = ConfigDict(frozen=True)

    user_id: str
    email: str
    name: Optional[str] = None
    email_verified: bool = False
    # Global SSO role (owner / super_admin / user / custom)
    role: Optional[str] = None
    # App-scoped roles: {"familyos": ["admin"], ...}
    roles: dict[str, list[str]] = Field(default_factory=dict)
    session_id: Optional[str] = None
    # True when role/roles came from a live SSO check, not the token.
    live: bool = False

    @property
    def role_name(self) -> Optional[str]:
        return self.role

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def is_admin(self) -> bool:
        return self.role in ADMIN_ROLES

    def app_roles(self, app_id: str) -> list[str]:
        return list(self.roles.get(app_id, []))

    def has_app_role(self, app_id: str, role: str) -> bool:
        return role in self.roles.get(app_id, [])

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> "SsoIdentity":
        role = claims.get("role") or claims.get("role_name")
        return cls(
            user_id=str(claims.get("user_id") or claims["sub"]),
            email=str(claims["email"]),
            name=claims.get("name"),
            email_verified=bool(claims.get("email_verified", False)),
            role=str(role).strip().lower() if role else None,
            roles=_clean_roles(claims.get("roles")),
            session_id=claims.get("sid"),
        )

    def with_live(self, me: dict[str, Any]) -> "SsoIdentity":
        role = me.get("role_name")
        return self.model_copy(
            update={
                "email": me.get("email") or self.email,
                "name": me.get("name") or self.name,
                "email_verified": bool(me.get("email_verified", self.email_verified)),
                "role": str(role).strip().lower() if role else None,
                "roles": _clean_roles(me.get("app_roles")),
                "live": True,
            }
        )


def _clean_roles(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    return {
        str(app): [str(r) for r in roles]
        for app, roles in value.items()
        if isinstance(roles, list)
    }
