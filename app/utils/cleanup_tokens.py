"""Cleanup expired auth tokens. Used by midnight cron and admin API."""

import logging
from typing import Any

from app.db.indexes import utcnow
from app.db.mongo import get_mongo_db
from app.models.action_limit import ActionLimitModel
from app.models.refresh_token import RefreshTokenModel
from app.models.token import (
    EmailChangeTokenModel,
    EmailVerificationTokenModel,
    PasswordResetTokenModel,
)

logger = logging.getLogger(__name__)


async def cleanup_expired_tokens() -> dict[str, int]:
    db = get_mongo_db()
    now = utcnow()
    counts = {
        "refresh_tokens": await RefreshTokenModel(db).delete_expired(now),
        "email_verification_tokens": await EmailVerificationTokenModel(db).delete_expired(
            now
        ),
        "password_reset_tokens": await PasswordResetTokenModel(db).delete_expired(now),
        "password_reset_tokens_used": await PasswordResetTokenModel(db).delete_used(),
        "email_change_tokens": await EmailChangeTokenModel(db).delete_expired(now),
        "action_limits": await ActionLimitModel(db).delete_expired(now),
    }
    total = sum(counts.values())
    if total:
        logger.info("Token cleanup removed %s docs: %s", total, counts)
    else:
        logger.info("Token cleanup: nothing to remove")
    return counts


def summarize_cleanup(counts: dict[str, int]) -> dict[str, Any]:
    return {
        "message": "Cleanup complete",
        "deleted_total": sum(counts.values()),
        "deleted": counts,
    }
