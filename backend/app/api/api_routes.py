"""Token-authenticated JSON API routes for CI, integrations, and webhooks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.models.project import Project
from backend.app.models.report import Report
from backend.app.schemas.scan import ScanApiSummaryRead, ScanCreateRequest
from backend.app.services.api_auth_service import require_api_token, require_webhook_token
from backend.app.services.job_runner import get_job_runner
from backend.app.services.preflight_service import RequirementsPreflightService
from backend.app.services.query_service import ScanQueryService
from backend.app.services.scan_service import ScanService

api_router = APIRouter(prefix="/api/v1", tags=["api"])
settings = get_settings()


def _build_enqueue_response(scan_summary: ScanApiSummaryRead) -> dict[str, Any]:
    payload = scan_summary.model_dump(mode="json")
    payload["status_url"] = f"/api/v1/scans/{scan_summary.scan_id}/status"
    payload["detail_url"] = f"/api/v1/scans/{scan_summary.scan_id}"
    return payload


@api_router.post("/scans", dependencies=[Depends(require_api_token)], status_code=202)
def create_scan_api(
    request: Request,
    source_path: str = Form(""),
    project_id: str = Form(""),
    project_name: str = Form(""),
    source_label: str = Form(""),
    archive_file: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Create and enqueue a scan for CI/CD or service integrations."""
    scan_service = ScanService(db=db)
    source_path = source_path.strip()
    has_upload = bool(archive_file and archive_file.filename)
    if has_upload:
        scan_request = ScanCreateRequest(
            source_type="uploaded_archive",
            source_value=archive_file.filename or "",
            project_id=project_id or None,
            project_name=project_name.strip() or None,
            source_label=source_label.strip() or None,
        )
    elif source_path:
        if not settings.allow_api_local_path_scans:
            raise HTTPException(
                status_code=403,
                detail="API local path scans are disabled. Upload an archive instead.",
            )
        scan_request = ScanCreateRequest(
            source_type="local_path",
            source_value=source_path,
            project_id=project_id or None,
            project_name=project_name.strip() or None,
            source_label=source_label.strip() or None,
        )
    else:
        raise HTTPException(status_code=400, detail="Provide either a local path or a zip archive.")

    try:
        scan_job = scan_service.enqueue_scan(scan_request, upload=archive_file if has_upload else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    get_job_runner().enqueue(scan_job.id)
    summary = ScanQueryService(db).build_scan_api_summary(scan_job)
    return {"scan": _build_enqueue_response(summary)}


@api_router.get("/scans/{scan_job_id}/status", dependencies=[Depends(require_api_token)])
def get_scan_status_api(scan_job_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return a compact scan status payload for polling clients."""
    query_service = ScanQueryService(db)
    scan_job = query_service.load_scan_job(scan_job_id)
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {"scan": query_service.build_scan_api_summary(scan_job).model_dump(mode="json")}


@api_router.get("/scans/{scan_job_id}", dependencies=[Depends(require_api_token)])
def get_scan_detail_api(scan_job_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return a stable scan detail summary for integrations."""
    query_service = ScanQueryService(db)
    scan_job = query_service.load_scan_job(scan_job_id)
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    summary = query_service.build_scan_api_summary(scan_job).model_dump(mode="json")
    summary["severity_order"] = sorted(summary["severity_counts"].keys())
    return {"scan": summary}


@api_router.get("/scans/{scan_job_id}/comparison", dependencies=[Depends(require_api_token)])
def get_scan_comparison_api(
    scan_job_id: str,
    compare_to: str = "",
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return a deterministic grouped comparison against an older scan."""
    query_service = ScanQueryService(db)
    try:
        comparison = query_service.build_scan_comparison_api_summary(
            scan_job_id,
            compare_to_scan_id=compare_to or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if comparison is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {"comparison": comparison}


@api_router.get("/scans/{scan_job_id}/policy", dependencies=[Depends(require_api_token)])
def get_scan_policy_api(
    scan_job_id: str,
    compare_to: str = "",
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return deterministic policy evaluation for one scan."""
    query_service = ScanQueryService(db)
    try:
        policy = query_service.build_scan_policy_api_summary(
            scan_job_id,
            compare_to_scan_id=compare_to or None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if policy is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return {"policy": policy}


@api_router.get("/projects/{project_id}/scans", dependencies=[Depends(require_api_token)])
def list_project_scans_api(
    project_id: str,
    limit: int = 10,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List recent scans for one project."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    limit = min(max(limit, 1), 50)
    scans = ScanQueryService(db).list_recent_scans_for_project_api(project_id=project_id, limit=limit)
    return {
        "project": {"id": project.id, "name": project.name},
        "scans": [scan.model_dump(mode="json") for scan in scans],
    }


@api_router.get("/projects/{project_id}/trends", dependencies=[Depends(require_api_token)])
def get_project_trends_api(
    project_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Return deterministic project-level trend summaries across scan history."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    limit = min(max(limit, 1), 100)
    trend_summary = ScanQueryService(db).build_project_trend_api_summary(project_id, limit=limit)
    if trend_summary is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"trend": trend_summary.model_dump(mode="json")}


@api_router.get("/scans/{scan_job_id}/reports/{report_format}", dependencies=[Depends(require_api_token)])
def download_report_api(
    scan_job_id: str,
    report_format: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download a generated report artifact over the token-authenticated API."""
    report = (
        db.execute(
            select(Report).where(
                Report.scan_job_id == scan_job_id,
                Report.report_format == report_format.lower(),
            )
        )
        .scalars()
        .first()
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    normalized_format = report_format.lower()
    media_type = "application/json" if normalized_format in {"json", "summary"} else "text/html"
    filename = (
        f"scan-{scan_job_id}.summary.json"
        if normalized_format == "summary"
        else f"scan-{scan_job_id}.{normalized_format}"
    )
    return FileResponse(path=report.path, filename=filename, media_type=media_type)


@api_router.get("/worker/status", dependencies=[Depends(require_api_token)])
def worker_status_api() -> dict[str, Any]:
    """Return basic worker and cleanup visibility for operators and CI tooling."""
    return {"worker": get_job_runner().status_snapshot()}


@api_router.get("/requirements/status", dependencies=[Depends(require_api_token)])
def requirements_status_api() -> dict[str, Any]:
    """Return operator-facing scanner/tool availability summary."""
    return {"requirements": RequirementsPreflightService(settings).build_summary()}


@api_router.post("/webhooks/gitlab", dependencies=[Depends(require_webhook_token)], status_code=202)
async def gitlab_webhook(
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Validate a webhook token and optionally enqueue a local-path scan."""
    payload = await request.json()
    source_path = str(payload.get("source_path", "")).strip()
    if source_path:
        if not settings.allow_api_local_path_scans:
            raise HTTPException(
                status_code=403,
                detail="Webhook local path scans are disabled.",
            )
        scan_request = ScanCreateRequest(
            source_type="local_path",
            source_value=source_path,
            project_id=payload.get("project_id"),
            project_name=payload.get("project_name"),
            source_label=payload.get("source_label") or payload.get("ref"),
        )
        try:
            scan_job = ScanService(db=db).enqueue_scan(scan_request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        get_job_runner().enqueue(scan_job.id)
        summary = ScanQueryService(db).build_scan_api_summary(scan_job)
        return {
            "accepted": True,
            "queued": True,
            "scan": _build_enqueue_response(summary),
        }
    return {
        "accepted": True,
        "queued": False,
        "message": (
            "Webhook validated. Automatic repository fetch is not implemented yet. "
            "Provide source_path only in trusted internal deployments or use the upload API from CI."
        ),
    }
