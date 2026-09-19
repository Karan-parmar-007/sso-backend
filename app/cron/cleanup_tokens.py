"""Cron job: cleanup expired auth tokens (midnight).

Logic lives in ``app.utils.cleanup_tokens`` — this module only schedules the call.
"""

import logging

from app.utils.cleanup_tokens import cleanup_expired_tokens

logger = logging.getLogger(__name__)


async def run_cleanup_expired_tokens() -> dict[str, int]:
    """APScheduler entrypoint — delegates to utils."""
    logger.info("[CRON] Running expired token cleanup")
    return await cleanup_expired_tokens()
