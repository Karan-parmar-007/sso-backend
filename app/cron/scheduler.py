"""APScheduler — register and run all cron jobs."""

import logging
from zoneinfo import ZoneInfo

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.config import security_settings
from app.cron.cleanup_tokens import run_cleanup_expired_tokens

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def _timezone():
    name = (security_settings.TOKEN_CLEANUP_TIMEZONE or "").strip()
    if name:
        return ZoneInfo(name)
    return ZoneInfo("UTC")


def start_scheduler() -> None:
    global _scheduler
    if not security_settings.TOKEN_CLEANUP_ENABLED:
        logger.info("[SCHEDULER] Token cleanup disabled (TOKEN_CLEANUP_ENABLED=false)")
        return
    if _scheduler and _scheduler.running:
        return

    hour = security_settings.TOKEN_CLEANUP_HOUR
    tz = _timezone()
    _scheduler = AsyncIOScheduler(timezone=tz)
    _scheduler.add_job(
        run_cleanup_expired_tokens,
        trigger=CronTrigger(hour=hour, minute=0, timezone=tz),
        id="cleanup_expired_tokens",
        name="Cleanup expired auth tokens",
        replace_existing=True,
        misfire_grace_time=3600,
    )
    _scheduler.start()
    logger.info(
        "[SCHEDULER] APScheduler started — cleanup daily at %02d:00 (%s)",
        hour,
        tz,
    )


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("[SCHEDULER] APScheduler stopped")
    _scheduler = None
