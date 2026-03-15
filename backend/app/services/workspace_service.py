"""Prepare scan workspaces from local paths or uploaded archives."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import zipfile

from fastapi import UploadFile

from backend.app.core.config import get_settings
from backend.app.schemas.scan import PreparedScanRequest, ScanCreateRequest

settings = get_settings()


@dataclass(slots=True)
class ScanWorkspace:
    """Prepared scan input backed by either a local path or an extracted archive."""

    source_type: str
    source_value: str
    source_filename: str | None
    project_name: str
    workspace_path: Path

    def as_request(self) -> PreparedScanRequest:
        """Convert the workspace metadata into the shared prepared request schema."""
        return PreparedScanRequest(
            source_type=self.source_type,
            source_value=self.source_value,
            source_filename=self.source_filename,
            project_name=self.project_name,
            workspace_path=self.workspace_path,
        )


class WorkspaceService:
    """Prepare per-scan workspaces from trusted local paths or uploaded zip archives."""

    def prepare(
        self,
        scan_id: str,
        request: ScanCreateRequest,
        upload: UploadFile | None = None,
    ) -> PreparedScanRequest:
        """Resolve the source into a concrete workspace path for scanners."""
        if request.source_type == "local_path":
            return self._prepare_local_path(request)
        if request.source_type == "uploaded_archive":
            if upload is None:
                raise ValueError("Archive upload is required for uploaded archive scans.")
            return self._prepare_uploaded_archive(scan_id=scan_id, request=request, upload=upload)
        raise ValueError(f"Unsupported scan source type: {request.source_type}")

    def _prepare_local_path(self, request: ScanCreateRequest) -> PreparedScanRequest:
        if not settings.allow_local_path_scans:
            raise ValueError("Local path scans are disabled by configuration.")
        if not request.source_value.strip():
            raise ValueError("Local scan path is required.")
        target_path = Path(request.source_value).expanduser().resolve()
        if not target_path.exists():
            raise ValueError(f"Scan path does not exist: {target_path}")
        return ScanWorkspace(
            source_type="local_path",
            source_value=str(target_path),
            source_filename=None,
            project_name=request.project_name or target_path.name,
            workspace_path=target_path,
        ).as_request()

    def _prepare_uploaded_archive(
        self,
        scan_id: str,
        request: ScanCreateRequest,
        upload: UploadFile,
    ) -> PreparedScanRequest:
        if not settings.allow_archive_uploads:
            raise ValueError("Archive uploads are disabled by configuration.")
        filename = (upload.filename or "").strip()
        if not filename.lower().endswith(".zip"):
            raise ValueError("Only .zip project archives are supported.")

        upload_dir = settings.scan_upload_dir / scan_id
        workspace_dir = settings.scan_workspace_dir / scan_id
        extracted_dir = workspace_dir / "source"
        upload_dir.mkdir(parents=True, exist_ok=True)
        extracted_dir.mkdir(parents=True, exist_ok=True)

        archive_name = self._sanitize_filename(filename)
        archive_path = upload_dir / archive_name
        with archive_path.open("wb") as destination:
            shutil.copyfileobj(upload.file, destination)
        upload.file.close()

        if not zipfile.is_zipfile(archive_path):
            archive_path.unlink(missing_ok=True)
            raise ValueError("Uploaded file is not a valid zip archive.")

        self.safe_extract_zip(archive_path, extracted_dir)
        project_name = request.project_name or Path(filename).stem
        return ScanWorkspace(
            source_type="uploaded_archive",
            source_value=str(archive_path),
            source_filename=filename,
            project_name=project_name,
            workspace_path=extracted_dir,
        ).as_request()

    def safe_extract_zip(self, archive_path: Path, destination: Path) -> None:
        """Extract zip contents while rejecting zip-slip paths."""
        destination = destination.resolve()
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                member_name = member.filename
                if not member_name or member_name.endswith("/"):
                    self._ensure_member_path(destination, member_name).mkdir(
                        parents=True,
                        exist_ok=True,
                    )
                    continue

                target_path = self._ensure_member_path(destination, member_name)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target_path.open("wb") as target:
                    shutil.copyfileobj(source, target)

    def _ensure_member_path(self, destination: Path, member_name: str) -> Path:
        member_path = (destination / member_name).resolve()
        if not str(member_path).startswith(f"{destination}{os.sep}"):
            if member_path != destination:
                raise ValueError(f"Unsafe archive entry detected: {member_name}")
        if Path(member_name).is_absolute():
            raise ValueError(f"Unsafe archive entry detected: {member_name}")
        return member_path

    def _sanitize_filename(self, filename: str) -> str:
        safe_name = Path(filename).name
        if not safe_name:
            raise ValueError("Uploaded archive filename is invalid.")
        return safe_name
