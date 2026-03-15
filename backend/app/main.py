"""FastAPI entrypoint for the internal security audit platform."""

from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from backend.app.api.api_routes import api_router
from backend.app.api.routes import router
from backend.app.core.config import get_settings
from backend.app.core.database import init_db
from backend.app.services.job_runner import get_job_runner
from backend.app.services.preflight_service import RequirementsPreflightService


def configure_logging() -> None:
    """Configure structured-enough logging for the MVP."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    configure_logging()
    init_db()
    logger = logging.getLogger("preflight")
    requirements_summary = RequirementsPreflightService(settings).build_summary()
    if requirements_summary["all_available"]:
        logger.info("scanner preflight ok: all configured tools available")
    else:
        for warning in requirements_summary["warnings"]:
            logger.warning("scanner preflight warning: %s", warning)
    ai_summary = requirements_summary["ai"]
    logger.info(
        "ai readiness: %s (provider=%s model=%s)",
        ai_summary["status_label"],
        ai_summary["provider"],
        ai_summary["model"] or "n/a",
    )
    for warning in ai_summary["warnings"]:
        logger.warning("ai readiness warning: %s", warning)
    job_runner = get_job_runner()
    job_runner.start()
    if settings.cleanup_on_startup:
        job_runner.run_cleanup_once()
    job_runner.recover_jobs()
    yield
    job_runner.stop()


settings = get_settings()
app = FastAPI(title=settings.app_name, debug=settings.app_debug, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    max_age=settings.session_max_age_seconds,
    same_site="lax",
    https_only=settings.session_cookie_secure,
    session_cookie="audit_session",
)
app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")
app.include_router(router)
app.include_router(api_router)
