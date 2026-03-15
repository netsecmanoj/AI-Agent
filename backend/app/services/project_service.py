"""Project management services for admin users."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from backend.app.models.project import Project
from backend.app.models.scan import ScanJob
from backend.app.services.policy_service import PolicyEvaluationService
from backend.app.services.trend_service import ProjectTrendService


class ProjectService:
    """Create, update, list, and inspect projects."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.trend_service = ProjectTrendService(db)
        self.policy_service = PolicyEvaluationService()

    def list_projects(self) -> list[Project]:
        """Return all projects ordered by name."""
        return self.db.execute(select(Project).order_by(Project.name.asc())).scalars().all()

    def get_project(self, project_id: str) -> Project | None:
        """Load one project with its scans."""
        return (
            self.db.execute(
                select(Project)
                .where(Project.id == project_id)
                .options(selectinload(Project.scan_jobs))
            )
            .scalars()
            .first()
        )

    def create_project(self, name: str, description: str | None = None) -> Project:
        """Create a new project."""
        name = name.strip()
        if not name:
            raise ValueError("Project name is required.")
        existing = self.db.execute(select(Project).where(Project.name == name)).scalars().first()
        if existing:
            raise ValueError(f"Project already exists: {name}")
        project = Project(name=name, description=(description or "").strip() or None, source_type="manual", source_value="")
        self.db.add(project)
        self.db.commit()
        self.db.refresh(project)
        return project

    def update_project(self, project_id: str, name: str, description: str | None = None) -> Project:
        """Update a project's basic metadata."""
        project = self.get_project(project_id)
        if project is None:
            raise ValueError("Project not found.")
        name = name.strip()
        if not name:
            raise ValueError("Project name is required.")
        conflict = (
            self.db.execute(select(Project).where(Project.name == name, Project.id != project_id))
            .scalars()
            .first()
        )
        if conflict:
            raise ValueError(f"Project already exists: {name}")
        project.name = name
        project.description = (description or "").strip() or None
        self.db.commit()
        self.db.refresh(project)
        return project

    def update_project_policy(
        self,
        project_id: str,
        *,
        preset: str | None,
        fail_severity_threshold: str | None,
        max_new_high_findings: str | None,
        max_weighted_risk_delta: str | None,
        warn_on_partial_scan: str | None,
        warn_on_any_high_findings: str | None,
    ) -> Project:
        """Update a project's policy preset and override fields."""
        project = self.get_project(project_id)
        if project is None:
            raise ValueError("Project not found.")

        normalized_preset = (preset or "").strip().lower() or None
        if normalized_preset and normalized_preset not in self.policy_service.preset_names():
            raise ValueError(f"Unsupported policy preset: {normalized_preset}")
        normalized_severity = (fail_severity_threshold or "").strip().lower() or None
        if normalized_severity and normalized_severity not in self.policy_service.severity_options:
            raise ValueError(f"Unsupported severity threshold: {normalized_severity}")

        project.policy_preset = normalized_preset
        project.policy_fail_severity_threshold = normalized_severity
        project.policy_max_new_high_findings = self._parse_optional_non_negative_int(
            max_new_high_findings,
            field_name="Max new high findings",
        )
        project.policy_max_weighted_risk_delta = self._parse_optional_non_negative_int(
            max_weighted_risk_delta,
            field_name="Max weighted risk delta",
        )
        project.policy_warn_on_partial_scan = self._parse_optional_bool(
            warn_on_partial_scan,
            field_name="Warn on partial scan",
        )
        project.policy_warn_on_any_high_findings = self._parse_optional_bool(
            warn_on_any_high_findings,
            field_name="Warn on any high findings",
        )
        self.db.commit()
        self.db.refresh(project)
        return project

    def build_projects_context(self) -> dict:
        """Return list-page context for projects."""
        projects = self.list_projects()
        project_counts = dict(
            self.db.execute(select(ScanJob.project_id, func.count(ScanJob.id)).group_by(ScanJob.project_id)).all()
        )
        return {"projects": projects, "project_scan_counts": project_counts}

    def build_project_detail_context(self, project_id: str) -> dict | None:
        """Return detail-page context for one project."""
        project = self.get_project(project_id)
        if project is None:
            return None
        scans = (
            self.db.execute(
                select(ScanJob)
                .where(ScanJob.project_id == project_id)
                .order_by(ScanJob.created_at.desc())
            )
            .scalars()
            .all()
        )
        comparison_targets = {
            scans[index].id: scans[index + 1].id
            for index in range(len(scans) - 1)
        }
        return {
            "project": project,
            "scans": scans,
            "comparison_targets": comparison_targets,
            "trend_summary": self.trend_service.build_project_trend(project_id).model_dump(mode="json"),
            "effective_policy": self.policy_service.resolve_project_policy(project).payload(),
            "policy_preset_options": self.policy_service.preset_names(),
            "policy_severity_options": self.policy_service.severity_options,
        }

    @staticmethod
    def _parse_optional_non_negative_int(value: str | None, *, field_name: str) -> int | None:
        candidate = (value or "").strip()
        if not candidate:
            return None
        try:
            parsed = int(candidate)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer.") from exc
        if parsed < 0:
            raise ValueError(f"{field_name} must be zero or greater.")
        return parsed

    @staticmethod
    def _parse_optional_bool(value: str | None, *, field_name: str) -> bool | None:
        candidate = (value or "").strip().lower()
        if not candidate:
            return None
        if candidate == "true":
            return True
        if candidate == "false":
            return False
        raise ValueError(f"{field_name} must be true, false, or blank.")
