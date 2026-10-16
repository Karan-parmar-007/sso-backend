"""Client IP, user agent and a coarse device label for the current request."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from fastapi import Request

from app.config import security_settings


@dataclass(frozen=True)
class RequestContext:
    ip: Optional[str]
    user_agent: str

    @property
    def device_label(self) -> str:
        return device_label(self.user_agent)


def client_ip(request: Request) -> Optional[str]:
    """Client IP as seen by the outermost trusted proxy.

    Proxies append to X-Forwarded-For, so only the right-most
    TRUSTED_PROXY_HOPS entries are trustworthy; anything to their left is
    client-controlled.
    """
    hops = max(0, security_settings.TRUSTED_PROXY_HOPS)
    forwarded = request.headers.get("x-forwarded-for")
    if hops and forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[-min(hops, len(parts))][:64]
    if request.client and request.client.host:
        return request.client.host[:64]
    return None


def request_context(request: Request) -> RequestContext:
    return RequestContext(
        ip=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "Unknown")[:500],
    )


_BROWSERS = (
    ("Edge", r"Edg/"),
    ("Opera", r"OPR/"),
    ("Firefox", r"Firefox/"),
    ("Chrome", r"Chrome/"),
    ("Safari", r"Safari/"),
)
_SYSTEMS = (
    ("iOS", r"iPhone|iPad"),
    ("Android", r"Android"),
    ("Windows", r"Windows"),
    ("macOS", r"Mac OS X|Macintosh"),
    ("Linux", r"Linux"),
)


def device_label(user_agent: str) -> str:
    browser = next((n for n, p in _BROWSERS if re.search(p, user_agent)), "Unknown browser")
    system = next((n for n, p in _SYSTEMS if re.search(p, user_agent)), "unknown OS")
    return f"{browser} on {system}"


def device_fingerprint(user_id: str, user_agent: str) -> str:
    """Stable across browser updates: browser family + OS only."""
    return hashlib.sha256(f"{user_id}|{device_label(user_agent)}".encode()).hexdigest()
