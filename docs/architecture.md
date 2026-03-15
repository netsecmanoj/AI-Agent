# Architecture

## Overview

Milestone 20 uses a single FastAPI application process with server-rendered templates, session-based local and OIDC-backed authentication, role-based access control, token-authenticated JSON APIs, multi-ecosystem coverage for Python, Node, Dart, Flutter, Maven, Composer, Go, and .NET, deterministic framework-aware review for Spring, Laravel, Express, and Flutter app code/config, deterministic grouped-finding views, deterministic scan-to-scan comparison, deterministic project-level trend aggregation, deterministic per-project policy resolution, an optional AI enrichment layer, deterministic mobile configuration review, an internal background worker thread, and conservative in-process retention cleanup. The design is intentionally modular so a future external queue, scheduler, richer SSO group mapping, deeper RBAC scopes, custom policy packs, additional ecosystem adapters, deeper framework-specific checks, deeper mobile-specific configuration checks, trend dashboards, or different AI backend can replace the current MVP components without rewriting the route or scan execution service boundaries.

## Runtime Flow

1. User opens the dashboard and submits a local filesystem path or uploads a zip archive.
2. The route handler validates input and delegates to `ScanService`.
3. `WorkspaceService` resolves the source into a scan workspace:
   local path scans use the source path directly;
   uploaded archives are stored under `uploads/<scan-id>/` and safely extracted under `workspaces/<scan-id>/source/`.
4. `ScanService` resolves or creates a `Project`, creates a `queued` `ScanJob`, and returns quickly to the client.
5. `InProcessJobRunner` enqueues the scan ID and a background worker thread pulls queued jobs from an internal queue.
6. The worker updates the scan to `running` and invokes `ScanService.execute_scan_job`.
7. `EcosystemDetectionService` inspects the workspace for Python, Node, Dart, Flutter, Maven, Composer, Go, and .NET markers plus audit-ready manifests such as `requirements.txt`, `package-lock.json`, `pubspec.lock`, `pom.xml`, `composer.lock`, `go.mod`, or `*.csproj`, and also records conservative framework hints for Spring, Laravel, Express, and Flutter apps.
8. `ScannerRegistry` supplies the shared base scanners plus ecosystem-specific and framework-aware adapters used by `ScanExecutionService`.
9. `ScanExecutionService` runs configured scanner adapters against the prepared workspace, including dependency or manifest-review tools only when the matching ecosystem is detected and audit-ready, Flutter-first analysis when Flutter markers are present, static mobile config review when Android/iOS Flutter app files exist, and parser-only framework review when supported framework hints are present.
10. Each adapter returns normalized findings through a shared contract.
11. Findings and tool execution records are persisted in SQLite through SQLAlchemy.
12. `FindingGroupingService` derives stable grouped finding summaries from the persisted normalized findings without deleting or rewriting raw records.
13. `ScanComparisonService` compares grouped findings across two scans from the same project and computes deterministic regression summaries.
14. `PolicyEvaluationService` resolves the effective policy from global defaults, project presets, and project overrides, then derives CI-oriented pass/fail/warn decisions from stored findings and optional comparison summaries.
15. `TrendService` derives per-project trend points from stored scans, grouped findings, comparison summaries, and effective policy results.
16. `AIEnrichmentService` optionally generates per-finding explanations/remediation guidance plus scan-level management summary content using grouped risk context and, when available, comparison deltas.
17. `OIDCService` optionally performs provider discovery, authorization-code exchange, and userinfo lookup for SSO logins.
18. `AuthService` validates the session, provisions local user records from identity claims, enforces role checks, and validates CSRF tokens for protected UI routes.
19. `APIAuthService` validates bearer tokens for `/api/v1` routes and webhook shared secrets for webhook intake.
20. `ScanQueryService` powers dashboard history filters, scan-detail finding filters, grouped findings, comparison summaries, trend summaries, policy summaries, and stable API responses.
21. `ProjectService` powers project creation, editing, project-level scan browsing, and trend visibility.
22. `ReportService` generates enriched JSON and HTML report artifacts after async execution completes.
23. `CleanupService` periodically deletes expired managed artifacts while skipping active scans and unmanaged paths.

## Key Components

- `backend/app/api/routes.py`
  Thin HTTP layer for health, dashboard, scan creation, scan detail, and report downloads.
- `backend/app/core/config.py`
  Central environment-driven configuration with filesystem path helpers.
- `backend/app/core/database.py`
  SQLAlchemy engine/session setup and bootstrap logic.
- `backend/app/models/user.py`
  Local or OIDC-backed user model with additive identity metadata and role assignment.
- `backend/app/scanners/base.py`
  Shared adapter contract for pluggable scanners.
- `backend/app/scanners/semgrep.py`
  Semgrep implementation with graceful degradation when the executable is absent.
- `backend/app/scanners/trivy.py`
  Trivy filesystem implementation with JSON normalization and graceful degradation.
- `backend/app/scanners/pip_audit.py`
  Python dependency audit implementation for requirements-style manifests.
- `backend/app/scanners/npm_audit.py`
  Node dependency audit implementation for `package-lock.json` and `npm-shrinkwrap.json`.
- `backend/app/scanners/dart_analyze.py`
  Flutter-first static analysis with Dart fallback, using analyzer output normalization.
- `backend/app/scanners/dart_pub_outdated.py`
  Dart/Flutter dependency freshness visibility through `pub outdated --json`.
- `backend/app/scanners/flutter_mobile_config.py`
  Deterministic file-based review of `AndroidManifest.xml` and `Info.plist` for first-pass mobile posture issues.
- `backend/app/scanners/maven_pom_review.py`
  Deterministic `pom.xml` review for floating versions, snapshot dependencies, insecure repositories, and system scope.
- `backend/app/scanners/composer_review.py`
  Deterministic `composer.json` / `composer.lock` review for abandoned packages and risky Composer config.
- `backend/app/scanners/go_mod_review.py`
  Deterministic `go.mod` review for replace directives, pseudo-versions, and toolchain configuration risks.
- `backend/app/scanners/dotnet_project_review.py`
  Deterministic `.csproj` and central package file review for floating versions, pre-release packages, and insecure restore sources.
- `backend/app/scanners/framework_review.py`
  Deterministic file- and source-based framework review for Spring, Laravel, Express, and Flutter app patterns.
- `backend/app/services/workspace_service.py`
  Handles trusted local paths, uploaded archive storage, and zip-slip-safe extraction.
- `backend/app/services/execution_service.py`
  Multi-scanner execution boundary that later async workers can call directly.
- `backend/app/services/ecosystem_service.py`
  Detects Python, Node, Dart, Flutter, Maven, Composer, Go, and .NET ecosystems using marker files and records audit-ready manifest metadata plus simple project-kind and framework hints.
- `backend/app/services/scanner_registry.py`
  Static registry that keeps shared base scanners and ecosystem-specific adapters pluggable without dynamic plugin infrastructure.
- `backend/app/services/query_service.py`
  Encapsulates scan-history filtering, finding browsing, grouped findings, and API serialization.
- `backend/app/services/grouping_service.py`
  Derives deterministic grouped finding views from normalized raw findings for UI, reports, APIs, and AI prompts.
- `backend/app/services/comparison_service.py`
  Compares grouped findings across scans from the same project and emits deterministic regression summaries.
- `backend/app/services/policy_service.py`
  Resolves effective project policy and evaluates scans against deterministic CI policy rules using severity counts and grouped comparison deltas.
- `backend/app/services/trend_service.py`
  Aggregates deterministic project-level trend points across scan history using stored findings, comparison, and policy services.
- `backend/app/services/job_runner.py`
  Manages the internal queue, worker thread, startup recovery, and worker-side execution.
- `backend/app/services/auth_service.py`
  Handles password hashing, local auth, OIDC-backed provisioning, session user lookup, role checks, and CSRF enforcement.
- `backend/app/services/oidc_service.py`
  Handles OIDC discovery, redirect generation, token exchange, and userinfo retrieval.
- `backend/app/services/api_auth_service.py`
  Handles service-token validation for the JSON API and shared-secret validation for webhooks.
- `backend/app/services/project_service.py`
  Handles project CRUD and project-centric history views.
- `backend/app/services/ai_service.py`
  Handles provider selection, prompt shaping, and failure-tolerant AI enrichment.
- `backend/app/services/cleanup_service.py`
  Applies retention rules to uploads, workspaces, and report artifacts.
- `backend/app/services/scan_service.py`
  Business logic for workspace preparation, queued scan creation, worker-side execution, persistence, source labels, and post-scan AI enrichment.
- `backend/app/services/report_service.py`
  JSON and HTML report generation.

## Data Model

- `Project`
  Stable identity for a scanned codebase.
- `User`
  Local or OIDC-backed account for the server-rendered UI, with an application role.
- `ScanJob`
  One scan execution against a project, including scan-level AI summary fields.
- `ToolExecution`
  One scanner run within a scan.
- `Finding`
  Tool-agnostic normalized issue record with optional AI explanation/remediation fields.
- `Report`
  Downloadable artifact metadata.

## Storage Notes

- Default database: SQLite for local MVP speed
- Migration target: PostgreSQL via `DATABASE_URL`
- Report output: filesystem-backed under `reports/generated`
- Upload path: stored under `uploads/<scan-id>/`
- Workspace path: extracted under `workspaces/<scan-id>/source/`
- Duration/source labels: stored on `scan_jobs` for richer scan-history views
- Queue metadata: `queued_at`, `worker_error`, and `retry_count` track async lifecycle state
- Session state: signed cookie-backed session with CSRF token in the same server-rendered flow
- AI metadata: additive fields on `scan_jobs` and `findings` track AI status, output, and safe error messages
- Grouped findings: computed in the service layer only; raw findings remain unchanged in persistence
- Scan comparisons: computed on demand or during report generation from stored scan data only
- API auth: env-driven bearer tokens for CI/service callers and a separate webhook shared secret
- Retention control: env-driven cleanup windows plus runner-maintained last-cleanup and storage-count summaries

## Extension Points

- Add scanner adapters under `backend/app/scanners/`
- Replace the in-process runner with a dedicated worker/queue backend when operational complexity justifies it
- Replace server-rendered pages with a separate frontend if needed
- Extend the current local-plus-OIDC session auth into richer group-to-role mappings or project-scoped RBAC without reshaping scan services
- Add more AI providers or route AI jobs to a separate worker without rewriting the scanner adapters
- Extend grouping to support scan-to-scan comparison and regression diffing without changing the stored raw finding model
- Extend comparison output into trend dashboards or historical baselines without changing grouped finding identity rules
- Replace coarse env-driven API tokens with scoped service accounts or stored API keys when needed
- Extend ecosystem detection and adapter registrations for Ruby, Rust, Elixir, Gradle, or other ecosystems and frameworks without changing the base scan pipeline
- Expand mobile posture checks to cover entitlements, manifest variants, and platform build settings without changing the normalized finding contract
- Move cleanup to an external scheduler when multi-instance coordination becomes necessary
