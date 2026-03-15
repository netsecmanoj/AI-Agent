"""HTTP routes for authentication, projects, dashboard, scans, and reports."""

import httpx
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.core.config import get_settings
from backend.app.core.database import get_db
from backend.app.models.project import Project
from backend.app.models.report import Report
from backend.app.models.scan import ScanJob
from backend.app.models.user import User
from backend.app.schemas.common import HealthResponse
from backend.app.schemas.scan import ScanCreateRequest
from backend.app.services.auth_service import (
    ROLE_ADMIN,
    ROLE_REVIEWER,
    ROLE_VIEWER,
    AuthService,
    ensure_csrf_token,
    require_admin_user,
    require_reviewer_user,
    require_viewer_user,
    user_can_manage_projects,
    user_can_submit_scans,
    validate_csrf_token,
)
from backend.app.services.job_runner import get_job_runner
from backend.app.services.oidc_service import OIDCService
from backend.app.services.preflight_service import RequirementsPreflightService
from backend.app.services.project_service import ProjectService
from backend.app.services.query_service import ScanQueryService
from backend.app.services.report_service import build_scan_context
from backend.app.services.scan_service import ScanService

router = APIRouter()
settings = get_settings()
templates = Jinja2Templates(directory=str(settings.templates_dir))


def _require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    return require_admin_user(request, db)


def _require_reviewer(request: Request, db: Session = Depends(get_db)) -> User:
    return require_reviewer_user(request, db)


def _require_viewer(request: Request, db: Session = Depends(get_db)) -> User:
    return require_viewer_user(request, db)


def _safe_next(next_value: str | None) -> str | None:
    if not next_value:
        return None
    if not next_value.startswith("/") or next_value.startswith("//"):
        return None
    return next_value


def _establish_user_session(request: Request, user: User) -> None:
    request.session.clear()
    request.session["user_id"] = user.id
    request.session["role"] = user.role
    request.session["auth_provider"] = user.auth_provider
    ensure_csrf_token(request)


def _render_login(
    request: Request,
    *,
    error: str | None = None,
    next_value: str = "",
) -> HTMLResponse:
    oidc_enabled = OIDCService().is_enabled()
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "next": _safe_next(next_value) or "",
            "csrf_token": ensure_csrf_token(request),
            "current_user": None,
            "oidc_enabled": oidc_enabled,
        },
        status_code=401 if error else 200,
    )


@router.get("/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    """Readiness-style health endpoint with a simple database check."""
    db.execute(select(1))
    return HealthResponse(status="ok", environment=settings.app_env, database="ok")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "") -> HTMLResponse:
    """Render the login page."""
    if request.session.get("user_id"):
        return RedirectResponse(url=_safe_next(next) or "/", status_code=303)
    return _render_login(request, next_value=next)


@router.post("/login", response_class=HTMLResponse, response_model=None)
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    next: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    """Authenticate an admin user and establish a session."""
    validate_csrf_token(request, csrf_token)
    auth_service = AuthService(db)
    user = auth_service.authenticate(username.strip(), password)
    if user is None:
        return _render_login(request, error="Invalid username or password.", next_value=next)
    _establish_user_session(request, user)
    return RedirectResponse(url=_safe_next(next) or "/", status_code=303)


@router.get("/auth/oidc/login")
def oidc_login(request: Request, next: str = "") -> RedirectResponse:
    """Start an OIDC login flow."""
    service = OIDCService()
    if not service.is_enabled():
        raise HTTPException(status_code=404, detail="OIDC login is not enabled.")
    authorization_url = service.build_authorization_redirect(request, next_path=_safe_next(next) or "/")
    return RedirectResponse(url=authorization_url, status_code=303)


@router.get("/auth/oidc/callback", name="oidc_callback", response_class=HTMLResponse)
def oidc_callback(
    request: Request,
    code: str = "",
    state: str = "",
    db: Session = Depends(get_db),
) -> Response:
    """Handle the OIDC authorization code callback and create a local session."""
    if not code or not state:
        return _render_login(request, error="OIDC callback did not include the required parameters.")
    try:
        claims = OIDCService().authenticate_callback(request, code=code, state=state)
        user = AuthService(db).provision_oidc_user(claims)
    except (ValueError, httpx.HTTPError) as exc:
        return _render_login(request, error=f"OIDC login failed: {exc}")
    _establish_user_session(request, user)
    return RedirectResponse(url=_safe_next(OIDCService().consume_next_path(request)) or "/", status_code=303)


@router.post("/logout", response_model=None)
def logout(
    request: Request,
    csrf_token: str = Form(""),
) -> RedirectResponse:
    """Clear the current session."""
    validate_csrf_token(request, csrf_token)
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    project: str = "",
    status: str = "",
    source_type: str = "",
    severity: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> HTMLResponse:
    """Render the minimal dashboard with recent scan activity."""
    query_service = ScanQueryService(db)
    context: dict[str, Any] = query_service.build_dashboard_context(
        request=request,
        project=project or None,
        status=status or None,
        source_type=source_type or None,
        severity=severity or None,
    )
    context.update(
        {
            "allow_local_path_scans": settings.allow_local_path_scans,
            "allow_archive_uploads": settings.allow_archive_uploads,
            "worker_status": get_job_runner().status_snapshot(),
            "requirements_summary": RequirementsPreflightService(settings).build_summary(),
            "current_user": current_user,
            "csrf_token": ensure_csrf_token(request),
            "can_submit_scans": user_can_submit_scans(current_user),
        }
    )
    return templates.TemplateResponse(request, "dashboard.html", context)


@router.post("/scans", response_class=HTMLResponse, response_model=None)
def create_scan(
    request: Request,
    source_path: str = Form(""),
    project_id: str = Form(""),
    project_name: str = Form(""),
    archive_file: UploadFile | None = File(default=None),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_reviewer),
) -> Response:
    """Create and enqueue a scan from a local path or uploaded archive."""
    validate_csrf_token(request, csrf_token)
    scan_service = ScanService(db=db)
    source_path = source_path.strip()
    has_upload = bool(archive_file and archive_file.filename)
    if has_upload:
        scan_request = ScanCreateRequest(
            source_type="uploaded_archive",
            source_value=archive_file.filename or "",
            project_id=project_id or None,
            project_name=project_name.strip() or None,
        )
    elif source_path:
        scan_request = ScanCreateRequest(
            source_type="local_path",
            source_value=source_path,
            project_id=project_id or None,
            project_name=project_name.strip() or None,
        )
    else:
        return _render_dashboard_error(
            request=request,
            db=db,
            error_message="Provide either a local path or a zip archive.",
        )
    try:
        scan_job = scan_service.enqueue_scan(scan_request, upload=archive_file if has_upload else None)
    except ValueError as exc:
        return _render_dashboard_error(request=request, db=db, error_message=str(exc))
    get_job_runner().enqueue(scan_job.id)
    return RedirectResponse(url=f"/scans/{scan_job.id}", status_code=303)


@router.get("/scans/{scan_job_id}", response_class=HTMLResponse)
def scan_detail(
    scan_job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> HTMLResponse:
    """Render the scan detail page with findings and tool execution state."""
    query_service = ScanQueryService(db)
    try:
        raw_page = max(int(request.query_params.get("raw_page", "1")), 1)
        raw_limit = max(int(request.query_params.get("raw_limit", "100")), 1)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid raw finding pagination values.") from exc
    try:
        detail_context = query_service.load_scan_detail(
            scan_job_id,
            severity=request.query_params.get("severity") or None,
            tool=request.query_params.get("tool") or None,
            category=request.query_params.get("category") or None,
            finding_type=request.query_params.get("finding_type") or None,
            review_mode=request.query_params.get("review_mode") or None,
            ai_filter=request.query_params.get("ai_filter") or None,
            pattern_key=request.query_params.get("pattern_key") or None,
            hotspot_file=request.query_params.get("hotspot_file") or None,
            hotspot_module=request.query_params.get("hotspot_module") or None,
            compare_to_scan_id=request.query_params.get("compare_to") or None,
            raw_page=raw_page,
            raw_limit=raw_limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if detail_context is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    detail_context["request"] = request
    detail_context["auto_refresh_seconds"] = 5 if detail_context["is_active"] else None
    detail_context["current_user"] = current_user
    detail_context["csrf_token"] = ensure_csrf_token(request)
    return templates.TemplateResponse(request, "scan_detail.html", detail_context)


@router.get("/scans/{scan_job_id}/reports/{report_format}")
def download_report(
    scan_job_id: str,
    report_format: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> FileResponse:
    """Download a generated report for a scan."""
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


@router.get("/api/scans/{scan_job_id}")
def scan_detail_api(
    scan_job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> dict[str, Any]:
    """Return a normalized scan payload for later frontend/API expansion."""
    scan_job = (
        db.execute(
            select(ScanJob)
            .where(ScanJob.id == scan_job_id)
            .options(
                selectinload(ScanJob.project),
                selectinload(ScanJob.findings),
                selectinload(ScanJob.tool_executions),
            )
        )
        .scalars()
        .first()
    )
    if scan_job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return build_scan_context(scan_job)


@router.get("/projects", response_class=HTMLResponse)
def projects_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> HTMLResponse:
    """Render the projects list and create form."""
    service = ProjectService(db)
    context = service.build_projects_context()
    context.update(
        {
            "error": None,
            "current_user": current_user,
            "csrf_token": ensure_csrf_token(request),
            "can_manage_projects": user_can_manage_projects(current_user),
            "available_roles": [ROLE_ADMIN, ROLE_REVIEWER, ROLE_VIEWER],
        }
    )
    return templates.TemplateResponse(request, "projects.html", context)


@router.post("/projects", response_class=HTMLResponse, response_model=None)
def create_project(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
) -> Response:
    """Create a project."""
    validate_csrf_token(request, csrf_token)
    service = ProjectService(db)
    try:
        project = service.create_project(name=name, description=description)
    except ValueError as exc:
        context = service.build_projects_context()
        context.update(
            {
                "error": str(exc),
                "current_user": current_user,
                "csrf_token": ensure_csrf_token(request),
            }
        )
        return templates.TemplateResponse(request, "projects.html", context, status_code=400)
    return RedirectResponse(url=f"/projects/{project.id}", status_code=303)


@router.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_viewer),
) -> HTMLResponse:
    """Render one project's detail page."""
    context = ProjectService(db).build_project_detail_context(project_id)
    if context is None:
        raise HTTPException(status_code=404, detail="Project not found")
    context.update(
        {
            "error": None,
            "current_user": current_user,
            "csrf_token": ensure_csrf_token(request),
            "can_manage_projects": user_can_manage_projects(current_user),
        }
    )
    return templates.TemplateResponse(request, "project_detail.html", context)


@router.post("/projects/{project_id}", response_class=HTMLResponse, response_model=None)
def update_project(
    project_id: str,
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
) -> Response:
    """Update a project's basic metadata."""
    validate_csrf_token(request, csrf_token)
    service = ProjectService(db)
    try:
        project = service.update_project(project_id=project_id, name=name, description=description)
    except ValueError as exc:
        context = service.build_project_detail_context(project_id)
        if context is None:
            raise HTTPException(status_code=404, detail="Project not found")
        context.update(
            {
                "error": str(exc),
                "current_user": current_user,
                "csrf_token": ensure_csrf_token(request),
                "can_manage_projects": user_can_manage_projects(current_user),
            }
        )
        return templates.TemplateResponse(request, "project_detail.html", context, status_code=400)
    return RedirectResponse(url=f"/projects/{project.id}", status_code=303)


@router.post("/projects/{project_id}/policy", response_class=HTMLResponse, response_model=None)
def update_project_policy(
    project_id: str,
    request: Request,
    policy_preset: str = Form(""),
    policy_fail_severity_threshold: str = Form(""),
    policy_max_new_high_findings: str = Form(""),
    policy_max_weighted_risk_delta: str = Form(""),
    policy_warn_on_partial_scan: str = Form(""),
    policy_warn_on_any_high_findings: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
) -> Response:
    """Update one project's effective policy preset and overrides."""
    validate_csrf_token(request, csrf_token)
    service = ProjectService(db)
    try:
        project = service.update_project_policy(
            project_id=project_id,
            preset=policy_preset,
            fail_severity_threshold=policy_fail_severity_threshold,
            max_new_high_findings=policy_max_new_high_findings,
            max_weighted_risk_delta=policy_max_weighted_risk_delta,
            warn_on_partial_scan=policy_warn_on_partial_scan,
            warn_on_any_high_findings=policy_warn_on_any_high_findings,
        )
    except ValueError as exc:
        context = service.build_project_detail_context(project_id)
        if context is None:
            raise HTTPException(status_code=404, detail="Project not found")
        context.update(
            {
                "error": str(exc),
                "current_user": current_user,
                "csrf_token": ensure_csrf_token(request),
                "can_manage_projects": user_can_manage_projects(current_user),
            }
        )
        return templates.TemplateResponse(request, "project_detail.html", context, status_code=400)
    return RedirectResponse(url=f"/projects/{project.id}", status_code=303)


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
) -> HTMLResponse:
    """Render a small admin user management page."""
    context = {
        "request": request,
        "current_user": current_user,
        "csrf_token": ensure_csrf_token(request),
        "error": None,
        "users": AuthService(db).list_users(),
        "available_roles": [ROLE_ADMIN, ROLE_REVIEWER, ROLE_VIEWER],
    }
    return templates.TemplateResponse(request, "admin_users.html", context)


@router.post("/admin/users/{user_id}/role", response_class=HTMLResponse, response_model=None)
def update_user_role(
    user_id: str,
    request: Request,
    role: str = Form(""),
    csrf_token: str = Form(""),
    db: Session = Depends(get_db),
    current_user: User = Depends(_require_admin),
) -> Response:
    """Update one user's role."""
    validate_csrf_token(request, csrf_token)
    auth_service = AuthService(db)
    try:
        auth_service.update_user_role(user_id, role.strip())
    except ValueError as exc:
        context = {
            "request": request,
            "current_user": current_user,
            "csrf_token": ensure_csrf_token(request),
            "error": str(exc),
            "users": auth_service.list_users(),
            "available_roles": [ROLE_ADMIN, ROLE_REVIEWER, ROLE_VIEWER],
        }
        return templates.TemplateResponse(request, "admin_users.html", context, status_code=400)
    return RedirectResponse(url="/admin/users", status_code=303)


def _render_dashboard_error(request: Request, db: Session, error_message: str) -> HTMLResponse:
    current_user = _require_viewer(request, db)
    query_service = ScanQueryService(db)
    context = query_service.build_dashboard_context(request=request, error=error_message)
    context.update(
        {
            "allow_local_path_scans": settings.allow_local_path_scans,
            "allow_archive_uploads": settings.allow_archive_uploads,
            "worker_status": get_job_runner().status_snapshot(),
            "requirements_summary": RequirementsPreflightService(settings).build_summary(),
            "current_user": current_user,
            "csrf_token": ensure_csrf_token(request),
            "can_submit_scans": user_can_submit_scans(current_user),
        }
    )
    return templates.TemplateResponse(request, "dashboard.html", context, status_code=400)
