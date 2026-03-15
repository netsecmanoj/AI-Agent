"""Tests for login, OIDC provisioning, and RBAC route enforcement."""

from fastapi.testclient import TestClient

from backend.app.core.config import get_settings
from backend.app.models.project import Project
from backend.app.models.scan import Finding, ScanJob, ToolExecution
from backend.app.services.auth_service import ROLE_ADMIN, ROLE_REVIEWER, ROLE_VIEWER, AuthService


def _login(client: TestClient, extract_csrf_token, username: str, password: str, next_path: str = "/") -> None:
    login_page = client.get("/login")
    csrf_token = extract_csrf_token(login_page.text)
    response = client.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token,
            "next": next_path,
        },
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_login_success_and_failure(isolated_app, create_admin_user, extract_csrf_token) -> None:
    app, _, runner = isolated_app
    create_admin_user()
    runner.stop()

    with TestClient(app) as client:
        login_page = client.get("/login")
        csrf_token = extract_csrf_token(login_page.text)

        failure = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "wrong-password",
                "csrf_token": csrf_token,
                "next": "",
            },
        )
        assert failure.status_code == 401

        login_page = client.get("/login")
        csrf_token = extract_csrf_token(login_page.text)
        success = client.post(
            "/login",
            data={
                "username": "admin",
                "password": "Password123!",
                "csrf_token": csrf_token,
                "next": "/",
            },
            follow_redirects=False,
        )
        assert success.status_code == 303
        assert success.headers["location"] == "/"


def test_protected_dashboard_requires_auth(isolated_app) -> None:
    app, _, runner = isolated_app
    runner.stop()

    with TestClient(app) as client:
        dashboard = client.get("/", follow_redirects=False)
        projects = client.get("/projects", follow_redirects=False)

    assert dashboard.status_code == 303
    assert dashboard.headers["location"].startswith("/login")
    assert projects.status_code == 303
    assert projects.headers["location"].startswith("/login")


def test_project_creation_and_listing_authenticated(
    isolated_app,
    create_admin_user,
    extract_csrf_token,
) -> None:
    app, _, runner = isolated_app
    create_admin_user()
    runner.stop()

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "admin", "Password123!", "/projects")

        projects_page = client.get("/projects")
        project_csrf = extract_csrf_token(projects_page.text)
        create_response = client.post(
            "/projects",
            data={
                "name": "platform-api",
                "description": "Internal platform service",
                "csrf_token": project_csrf,
            },
            follow_redirects=False,
        )
        assert create_response.status_code == 303

        listing = client.get("/projects")
        assert "platform-api" in listing.text
        assert "Internal platform service" in listing.text


def test_reviewer_can_submit_scans_but_cannot_manage_projects(
    isolated_app,
    create_user,
    extract_csrf_token,
    tmp_path,
) -> None:
    app, _, runner = isolated_app
    create_user("reviewer", role=ROLE_REVIEWER)
    runner.stop()
    repo_path = tmp_path / "repo"
    repo_path.mkdir()
    (repo_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "reviewer", "Password123!", "/")

        dashboard = client.get("/")
        assert 'name="source_path"' in dashboard.text
        assert "cannot submit new scans" not in dashboard.text

        project_page = client.get("/projects")
        project_csrf = extract_csrf_token(project_page.text)
        create_project = client.post(
            "/projects",
            data={
                "name": "should-not-work",
                "description": "forbidden",
                "csrf_token": project_csrf,
            },
            follow_redirects=False,
        )
        assert create_project.status_code == 403

        dashboard_csrf = extract_csrf_token(dashboard.text)
        create_scan = client.post(
            "/scans",
            data={
                "source_path": str(repo_path),
                "project_name": "reviewer-project",
                "csrf_token": dashboard_csrf,
            },
            follow_redirects=False,
        )
        assert create_scan.status_code == 303
        assert create_scan.headers["location"].startswith("/scans/")


def test_viewer_can_browse_but_cannot_submit_scans_or_access_admin(
    isolated_app,
    create_user,
    extract_csrf_token,
) -> None:
    app, _, runner = isolated_app
    create_user("viewer", role=ROLE_VIEWER)
    runner.stop()

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "viewer", "Password123!", "/")

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert 'name="source_path"' not in dashboard.text
        assert "cannot submit new scans" in dashboard.text

        dashboard_csrf = extract_csrf_token(dashboard.text)
        create_scan = client.post(
            "/scans",
            data={
                "source_path": "/tmp/should-not-run",
                "project_name": "viewer-project",
                "csrf_token": dashboard_csrf,
            },
            follow_redirects=False,
        )
        assert create_scan.status_code == 403

        admin_users = client.get("/admin/users", follow_redirects=False)
        assert admin_users.status_code == 403


def test_scan_detail_renders_review_tabs_and_ai_advisory_state(
    isolated_app,
    create_admin_user,
    extract_csrf_token,
) -> None:
    app, session_factory, runner = isolated_app
    settings = get_settings()
    create_admin_user()
    runner.stop()
    settings.ai_enabled = False
    settings.ai_provider = "disabled"

    with session_factory() as session:
        project = Project(name="scan-ui-project", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        scan_job = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            total_findings=2,
            ai_status="disabled",
        )
        session.add(scan_job)
        session.commit()
        session.refresh(scan_job)

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Undefined identifier",
                    description="Undefined identifier 'ThemeConfig'.",
                    severity="high",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/really/long/path/that/should/render/with/a/tooltip/and/not/blow/out/the/layout/theme_config.dart",
                    raw_payload={"rule_code": "undefined_identifier"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Android cleartext traffic is enabled",
                    description="The application manifest explicitly allows cleartext network traffic.",
                    severity="high",
                    category="mobile_network_security",
                    tool_name="flutter-mobile-config",
                    file_path="android/app/src/main/AndroidManifest.xml",
                    raw_payload={"check": "usesCleartextTraffic"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/home/presentation/view/home_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/auth/presentation/view/login_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/cart/presentation/view/cart_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/profile/presentation/view/profile_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/orders/presentation/view/orders_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Unused import",
                    description="Unused import 'package:flutter/material.dart'.",
                    severity="medium",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/features/product/presentation/view/product_view.dart",
                    raw_payload={"rule_code": "unused_import"},
                ),
                ToolExecution(
                    scan_job_id=scan_job.id,
                    tool_name="semgrep",
                    status="completed",
                    command="semgrep scan",
                ),
            ]
        )
        session.commit()
        scan_id = scan_job.id

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "admin", "Password123!", f"/scans/{scan_id}")
        dashboard = client.get("/")
        response = client.get(f"/scans/{scan_id}")

    assert dashboard.status_code == 200
    assert "AI readiness" in dashboard.text
    assert response.status_code == 200
    assert "Switch review mode quickly" in response.text
    assert "All findings" in response.text
    assert "Security risks" in response.text
    assert "Code correctness" in response.text
    assert "AI assistance" in response.text
    assert "advisory only" in response.text
    assert "Disabled" in response.text
    assert "Show more files" in response.text
    assert "truncate-path" in response.text
    assert 'title="lib/features/really/long/path/that/should/render/with/a/tooltip/and/not/blow/out/the/layout/theme_config.dart"' in response.text


def test_scan_detail_hides_raw_ai_connection_errors_during_drilldown(
    isolated_app,
    create_admin_user,
    extract_csrf_token,
) -> None:
    app, session_factory, runner = isolated_app
    create_admin_user()
    runner.stop()

    raw_ai_error = "[Errno 61] Connection refused while calling http://127.0.0.1:11434/v1/chat/completions"

    with session_factory() as session:
        project = Project(name="ai-failure-project", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)

        scan_job = ScanJob(
            project_id=project.id,
            project=project,
            status="completed",
            source_type="local_path",
            source_value="/tmp/demo",
            total_findings=2,
            ai_status="failed",
            ai_error=raw_ai_error,
        )
        session.add(scan_job)
        session.commit()
        session.refresh(scan_job)

        session.add_all(
            [
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Undefined identifier",
                    description="Undefined identifier 'ThemeConfig'.",
                    severity="high",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/main.dart",
                    raw_payload={"rule_code": "undefined_identifier"},
                    ai_status="failed",
                    ai_error=raw_ai_error,
                ),
                Finding(
                    project_id=project.id,
                    scan_job_id=scan_job.id,
                    title="Undefined identifier",
                    description="Undefined identifier 'ThemeConfig'.",
                    severity="high",
                    category="static_analysis",
                    tool_name="dart-flutter-analyze",
                    file_path="lib/feature.dart",
                    raw_payload={"rule_code": "undefined_identifier"},
                    ai_status="failed",
                    ai_error=raw_ai_error,
                ),
                ToolExecution(
                    scan_job_id=scan_job.id,
                    tool_name="semgrep",
                    status="completed",
                    command="semgrep scan",
                ),
            ]
        )
        session.commit()
        scan_id = scan_job.id

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "admin", "Password123!", f"/scans/{scan_id}")
        response = client.get(f"/scans/{scan_id}?hotspot_file=lib/main.dart")

    assert response.status_code == 200
    assert "AI enrichment failed because the configured AI endpoint was unreachable." in response.text
    assert "Check AI_ENABLED / AI_BASE_URL / provider availability." in response.text
    assert "[Errno 61] Connection refused" not in response.text


def test_admin_can_manage_user_roles(
    isolated_app,
    create_admin_user,
    create_user,
    extract_csrf_token,
) -> None:
    app, session_factory, runner = isolated_app
    create_admin_user()
    create_user("analyst", role=ROLE_VIEWER)
    runner.stop()

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "admin", "Password123!", "/admin/users")

        users_page = client.get("/admin/users")
        users_csrf = extract_csrf_token(users_page.text)
        role_update = client.post(
            "/admin/users/" + _user_id_for_username(session_factory, "analyst") + "/role",
            data={
                "role": ROLE_REVIEWER,
                "csrf_token": users_csrf,
            },
            follow_redirects=False,
        )
        assert role_update.status_code == 303

        with session_factory() as session:
            user = AuthService(session).get_user_by_username("analyst")
            assert user is not None
            assert user.role == ROLE_REVIEWER


def test_admin_can_update_project_policy_settings(
    isolated_app,
    create_admin_user,
    extract_csrf_token,
) -> None:
    app, session_factory, runner = isolated_app
    create_admin_user()
    runner.stop()

    with session_factory() as session:
        project = Project(name="policy-project", source_type="manual", source_value="")
        session.add(project)
        session.commit()
        session.refresh(project)
        project_id = project.id

    with TestClient(app) as client:
        _login(client, extract_csrf_token, "admin", "Password123!", f"/projects/{project_id}")

        project_page = client.get(f"/projects/{project_id}")
        csrf_token = extract_csrf_token(project_page.text)
        update_response = client.post(
            f"/projects/{project_id}/policy",
            data={
                "policy_preset": "strict",
                "policy_fail_severity_threshold": "",
                "policy_max_new_high_findings": "1",
                "policy_max_weighted_risk_delta": "2",
                "policy_warn_on_partial_scan": "false",
                "policy_warn_on_any_high_findings": "",
                "csrf_token": csrf_token,
            },
            follow_redirects=False,
        )
        assert update_response.status_code == 303

        updated_page = client.get(f"/projects/{project_id}")
        assert "Effective project policy" in updated_page.text
        assert "strict" in updated_page.text

    with session_factory() as session:
        project = session.get(Project, project_id)
        assert project is not None
        assert project.policy_preset == "strict"
        assert project.policy_max_new_high_findings == 1
        assert project.policy_max_weighted_risk_delta == 2
        assert project.policy_warn_on_partial_scan is False


def test_oidc_callback_provisions_user_and_establishes_session(
    isolated_app,
    monkeypatch,
) -> None:
    app, session_factory, runner = isolated_app
    runner.stop()

    monkeypatch.setattr("backend.app.api.routes.OIDCService.is_enabled", lambda self: True)
    monkeypatch.setattr(
        "backend.app.api.routes.OIDCService.authenticate_callback",
        lambda self, request, code, state: {
            "sub": "oidc-subject-1",
            "preferred_username": "sso.reviewer",
            "email": "reviewer@example.com",
            "name": "SSO Reviewer",
            "groups": ["sec-reviewers"],
        },
    )

    settings = get_settings()
    monkeypatch.setattr(settings, "oidc_reviewer_groups_raw", "sec-reviewers")
    monkeypatch.setattr(settings, "oidc_default_role", ROLE_VIEWER)

    with TestClient(app) as client:
        callback = client.get("/auth/oidc/callback?code=test-code&state=test-state", follow_redirects=False)
        assert callback.status_code == 303
        assert callback.headers["location"] == "/"

        dashboard = client.get("/")
        assert dashboard.status_code == 200
        assert "SSO Reviewer" in dashboard.text

    with session_factory() as session:
        user = AuthService(session).get_user_by_external_identity("oidc", "oidc-subject-1")
        assert user is not None
        assert user.username == "sso.reviewer"
        assert user.role == ROLE_REVIEWER
        assert user.email == "reviewer@example.com"
        assert user.display_name == "SSO Reviewer"


def test_oidc_login_redirects_to_provider(isolated_app, monkeypatch) -> None:
    app, _, runner = isolated_app
    runner.stop()

    monkeypatch.setattr("backend.app.api.routes.OIDCService.is_enabled", lambda self: True)
    monkeypatch.setattr(
        "backend.app.api.routes.OIDCService.build_authorization_redirect",
        lambda self, request, next_path: "https://idp.example.test/authorize?state=test",
    )

    with TestClient(app) as client:
        response = client.get("/auth/oidc/login?next=/projects", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "https://idp.example.test/authorize?state=test"


def _user_id_for_username(session_factory, username: str) -> str:
    with session_factory() as session:
        user = AuthService(session).get_user_by_username(username)
        assert user is not None
        return user.id
