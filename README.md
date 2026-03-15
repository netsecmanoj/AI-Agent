# Internal Security Audit Platform

Self-hosted MVP for internal multi-ecosystem code and configuration security auditing. The current implementation provides a FastAPI service with a server-rendered dashboard, session-based local and OIDC-backed authentication, role-based access control, project management, project-level trend visibility, health/readiness checks, SQLite-backed persistence, archive upload ingestion, ecosystem-aware dependency enrichment for Python, Node, Dart, Flutter, Maven, Composer, Go, and .NET / NuGet, optional AI assistance, shared Semgrep/Trivy plus ecosystem-specific adapters, deterministic mobile config review, deterministic framework-aware review for Spring, Laravel, Express, and Flutter app structures, an in-process background job runner, conservative retention cleanup, and downloadable JSON/HTML reports.

## Purpose

This project is intended to help engineering and security teams run repeatable security scans against application source trees and normalize findings into a developer-friendly workflow. The long-term target includes multiple scanners, management summaries, GitLab CI integration, authentication, and AI-assisted remediation guidance.

The platform is designed as a shared audit pipeline with pluggable ecosystem adapters selected from repository contents. Findings from every supported ecosystem flow through the same normalization, grouping, comparison, report, AI, UI, and API layers.

## Milestone 1 Scope

- FastAPI application skeleton
- Health endpoint at `/health`
- Jinja-rendered dashboard at `/`
- SQLite-backed models for `Project`, `ScanJob`, `Finding`, `ToolExecution`, and `Report`
- Scanner adapter interface
- Semgrep adapter with graceful fallback when Semgrep is not installed
- JSON and HTML report generation
- Dockerfile and `docker-compose.yml`
- Basic test coverage

## Milestone 2 Scope

- Zip archive upload from the dashboard
- Safe zip extraction into a per-scan workspace
- Reusable scan execution boundary for multi-tool orchestration
- Trivy filesystem scanning alongside Semgrep
- Multi-tool scan statuses and richer scan detail views
- Tests for upload ingestion, zip-slip rejection, and Trivy normalization

## Milestone 3 Scope

- Ecosystem detection for Python and Node workspaces
- Python dependency auditing through optional `pip-audit`
- Dashboard scan-history filters by project, status, source type, and severity
- Scan-detail finding filters by severity, tool, and category
- Richer report metadata including grouped findings, tool summaries, and duration
- Tests for ecosystem detection, dependency parsing, query filtering, and report shape

## Milestone 4 Scope

- In-process queue and worker thread for async scan execution
- Fast enqueue flow for `POST /scans`
- Explicit scan lifecycle states and worker error tracking
- Restart recovery for queued and interrupted running jobs
- Refresh-friendly UI for queued/running scans
- Tests for enqueue flow, worker transitions, and async report generation

## Milestone 5 Scope

- Session-based admin authentication with password hashing
- Login and logout flows for the server-rendered UI
- Auth protection for scans, reports, and project pages
- Project create/list/view/edit flows
- Project-aware scan submission and browsing
- Admin bootstrap script for the first local user

## Milestone 6 Scope

- Optional AI assistance layer for findings and management summaries
- Pluggable provider abstraction with disabled and OpenAI-compatible modes
- Per-finding AI explanation and remediation guidance
- Per-scan management summary, top risks, and next steps
- Failure-tolerant AI enrichment in the worker after scanners complete
- AI output surfaced in scan detail pages and generated reports

## Milestone 7 Scope

- Token-authenticated JSON API for CI/CD and service integrations
- API scan submission, status polling, detail summary, and project scan listing
- Token-protected report downloads for external clients
- Minimal validated webhook intake for future automation
- GitLab CI upload-and-poll example for self-hosted deployments

## Milestone 8 Scope

- Node/JavaScript dependency auditing through optional `npm audit`
- Broader ecosystem detection metadata for Python and Node workspaces
- Consistent dependency finding normalization across Python and Node
- Clearer ecosystem and dependency-tool coverage in UI, API, and reports
- Tests for Node detection, npm parsing, and missing-tool behavior

## Milestone 9 Scope

- Configurable retention controls for uploads, workspaces, and reports
- Safe cleanup service that skips active scans and unmanaged paths
- Worker health visibility in the dashboard and JSON API
- Managed storage counts and last cleanup summary for operators
- Tests for cleanup safety and worker status reporting

## Milestone 10 Scope

- Deterministic grouping of duplicate or similar findings as a derived view
- Grouped finding presentation in the scan detail page, JSON API, and reports
- Scan-level AI summaries refined to use grouped risk context
- Raw finding persistence and per-tool traceability preserved alongside grouped summaries
- Tests for grouping logic, grouped report/API output, and grouped AI input behavior

## Milestone 11 Scope

- Deterministic scan-to-scan comparison for scans from the same project
- New, resolved, and unchanged grouped finding summaries
- Severity and grouped-risk deltas in the UI, JSON API, and generated reports
- Default comparison against the immediately previous scan, with optional older-scan selection
- Comparison-aware AI scan context for better regression/improvement summaries

## Milestone 12 Scope

- Deterministic Dart and Flutter ecosystem detection
- Flutter-first static analysis with Dart fallback
- Dart/Flutter dependency freshness visibility through `pub outdated`
- Shared normalization for Flutter/Dart findings in UI, API, grouping, and comparison flows
- Tests for Dart/Flutter detection, parsing, and report/API ecosystem visibility

## Milestone 13 Scope

- AndroidManifest.xml review for first-pass risky settings in Flutter apps
- iOS Info.plist review for first-pass ATS and file-sharing posture issues
- Mobile-oriented normalized findings in the existing UI/API/report/grouping/comparison flows
- Deterministic file-based checks with no builds, tests, or platform tool execution
- Tests for Android/iOS parsing, risky-setting detection, and skip behavior

## Milestone 14 Scope

- Shared scanner registry for base scanners and ecosystem-specific adapters
- Maven ecosystem detection plus deterministic `pom.xml` review
- Composer ecosystem detection plus deterministic `composer.json` and `composer.lock` review
- Broader ecosystem inventory visibility in report and API summaries
- Tests for Maven/Composer detection and parser-driven adapter behavior

## Milestone 15 Scope

- Go module ecosystem detection plus deterministic `go.mod` review
- .NET / NuGet ecosystem detection plus deterministic project-file review
- Shared scanner registry extension for Go and .NET adapters
- Broader ecosystem inventory visibility in report and API summaries
- Tests for Go/.NET detection and parser-driven adapter behavior

## Milestone 17 Scope

- OIDC/OAuth2 login flow with session-backed UI behavior after SSO
- User provisioning from identity claims with configurable role/group mapping
- Role-based access control for `admin`, `reviewer`, and `viewer`
- Admin user management page for role updates
- Local username/password bootstrap retained as a fallback path
- Tests for RBAC enforcement and OIDC provisioning

## Milestone 18 Scope

- Project-level trend summaries derived from stored scan history
- Severity counts, weighted risk, and policy outcome visibility over time
- Comparison-derived new, resolved, and unchanged grouped counts where prior scans exist
- Trend visibility on project detail pages
- Token-authenticated JSON API for project trend summaries
- Tests for deterministic trend aggregation and trend API shape

## Milestone 19 Scope

- Project-level policy presets and deterministic override fields
- Global env policy defaults retained as the fallback baseline
- Effective policy visibility on project pages, scan pages, reports, and APIs
- Admin-only project policy editing
- Tests for preset resolution, override precedence, and project-specific policy evaluation

## Milestone 20 Scope

- Deterministic framework detection for Spring, Laravel, Express, and Flutter app structures
- Shared `framework-review` adapter registered through the existing scanner registry
- Framework-specific config and source posture checks normalized through the shared finding model
- Additive framework inventory visibility in scan detail pages, reports, and APIs
- Tests for framework detection, parser-only review behavior, and report/API visibility

## Architecture

- `backend/app/main.py`: FastAPI entrypoint
- `backend/app/api/routes.py`: HTTP routes for auth, projects, dashboard, scans, and reports
- `backend/app/core/`: configuration and database setup
- `backend/app/models/`: SQLAlchemy data model
- `backend/app/services/`: auth, project management, scan orchestration, severity normalization, report generation
- `backend/app/services/workspace_service.py`: upload handling and safe extraction
- `backend/app/services/execution_service.py`: reusable multi-scanner execution boundary
- `backend/app/services/ecosystem_service.py`: deterministic ecosystem detection
- `backend/app/services/scanner_registry.py`: shared scanner registry for base and ecosystem adapters
- `backend/app/services/query_service.py`: scan history and finding browsing helpers
- `backend/app/services/grouping_service.py`: deterministic derived grouping for repeated findings
- `backend/app/services/comparison_service.py`: deterministic scan-to-scan grouped comparison and regression summaries
- `backend/app/services/policy_service.py`: deterministic CI-oriented policy evaluation for completed scans
- `backend/app/services/trend_service.py`: deterministic project-level trend aggregation across stored scans
- `backend/app/services/job_runner.py`: internal queue and worker lifecycle
- `backend/app/services/auth_service.py`: local auth, user provisioning, role checks, and CSRF helpers
- `backend/app/services/oidc_service.py`: OIDC discovery, redirect, token exchange, and userinfo retrieval
- `backend/app/services/project_service.py`: project CRUD and project-detail browsing
- `backend/app/services/ai_service.py`: optional AI provider abstraction and enrichment flow
- `backend/app/services/api_auth_service.py`: token auth for API and webhook routes
- `backend/app/services/cleanup_service.py`: retention selection and safe artifact cleanup
- `backend/app/scanners/`: scanner adapter contract and Semgrep integration
- `backend/app/scanners/trivy.py`: Trivy filesystem integration
- `backend/app/scanners/pip_audit.py`: Python dependency audit integration
- `backend/app/scanners/npm_audit.py`: Node dependency audit integration
- `backend/app/scanners/dart_analyze.py`: Flutter/Dart static analysis integration
- `backend/app/scanners/dart_pub_outdated.py`: Dart/Flutter dependency freshness integration
- `backend/app/scanners/flutter_mobile_config.py`: AndroidManifest.xml and Info.plist review for Flutter mobile posture checks
- `backend/app/scanners/maven_pom_review.py`: Maven `pom.xml` dependency/build review
- `backend/app/scanners/composer_review.py`: Composer manifest and lockfile review
- `backend/app/scanners/go_mod_review.py`: Go module manifest review
- `backend/app/scanners/dotnet_project_review.py`: .NET / NuGet project manifest review
- `backend/app/scanners/framework_review.py`: Shared deterministic framework-aware config and source review
- `backend/app/templates/`: server-rendered HTML views
- `backend/app/static/`: dashboard styles
- `scripts/bootstrap_admin.py`: admin bootstrap CLI
- `docs/architecture.md`: architecture notes
- `docs/api.md`: API usage and GitLab CI examples
- `docs/phases.md`: phased roadmap
- `docs/security-notes.md`: deployment and security cautions

## Setup

The application can run in two practical modes:

- Host mode: best when you want the widest scanner coverage, especially Flutter/Dart, and you are comfortable installing tools on the same machine as the app.
- Container mode: best for repeatable deployment. The main container installs Semgrep, Trivy, `pip-audit`, and Node/npm automatically. Flutter/Dart remain optional and are not bundled into the main image.

### Local macOS setup

1. Copy `.env.example` to `.env`.
2. Create a virtual environment.
3. Install Python dependencies.
4. Install baseline scanner tools.
5. Run the preflight check.
6. Bootstrap the first admin user.
7. Start the app.

```bash
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./scripts/setup_macos.sh
python scripts/check_requirements.py
python scripts/bootstrap_admin.py --username admin --password 'change-me-now'
uvicorn backend.app.main:app --reload
```

Open `http://127.0.0.1:8000`.

### Manual host setup

If you do not want to use the helper script:

```bash
cp .env.example .env
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pip-audit
```

Then install the host tools you want to enable:

- `semgrep`
- `trivy`
- `node` / `npm`
- `flutter` and `dart` if you want Flutter/Dart analysis and freshness coverage

Use absolute paths in `.env` only when the tools are not already on `PATH`. This is common on macOS for Homebrew or local Flutter SDK installs. Keep `.env.example` generic and set machine-specific paths only in your local `.env`.

### Running the preflight check

The preflight checker reports:

- available tools
- missing tools
- invalid configured paths
- which scanner coverage will be skipped or become partial

Manual usage:

```bash
python scripts/check_requirements.py
python scripts/check_requirements.py --json
python scripts/check_requirements.py --strict
```

`--strict` exits with a non-zero status if any configured scanner tool is missing or invalid. The app itself still starts even when some tools are unavailable.

### Starting the app locally

```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Sign in with the bootstrapped admin account, then submit a local filesystem path from the dashboard. The request persists a queued scan record and returns quickly; a background worker thread runs the actual scanners afterward.

You can also upload a `.zip` project archive. The server stores the archive under `uploads/<scan-id>/`, extracts it into `workspaces/<scan-id>/source/`, then the background worker runs scanners against the extracted workspace.

### Container deployment

```bash
cp .env.example .env
docker compose up --build
```

The service listens on `http://127.0.0.1:8000`.

The main container installs these tools automatically:

- Semgrep
- Trivy
- `pip-audit`
- Node/npm

The main container does not install these tools automatically:

- Flutter
- Dart

That keeps the default deployment image smaller and avoids bundling a heavy mobile SDK into every environment. Flutter/Dart coverage is therefore:

- supported in host mode
- optional in container mode
- visible as missing coverage through the preflight summary and scan tool-coverage issues

### Host mode vs container mode

- Host mode:
  - best coverage
  - easiest place to use absolute tool paths
  - recommended if Flutter/Dart scanning matters
- Container mode:
  - repeatable deployment with the practical baseline tools preinstalled
  - good for Semgrep, Trivy, Python dependency audit, and npm-based audit
  - Flutter/Dart remain documented and optional unless you build a custom image

## Admin Bootstrap

Create the first admin account with the bootstrap script:

```bash
python scripts/bootstrap_admin.py --username admin --password 'change-me-now'
```

You can also provide credentials through environment variables:

```bash
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_PASSWORD='change-me-now'
python scripts/bootstrap_admin.py
```

The script is idempotent for new usernames and fails if the user already exists.

## Troubleshooting

- `python: command not found`
  Use `python3` instead of `python` on macOS and many Linux hosts.

- `ModuleNotFoundError: No module named 'backend'`
  Start the app from the repository root and make sure the virtual environment is active before running `uvicorn backend.app.main:app`.

- `pip-audit` missing even though the app starts
  Install it into the same virtual environment that runs the app, then point `PIP_AUDIT_COMMAND` at that executable if it is not on `PATH`.

- Scans complete as `Completed with tool issues`
  This usually means one or more optional scanners were unavailable or failed. Run `python scripts/check_requirements.py` and review the dashboard scanner requirements panel.

- macOS tools installed under `/opt/homebrew/bin/...`
  Set the corresponding command variable in your local `.env`, for example `SEMGREP_COMMAND=/opt/homebrew/bin/semgrep`.

- Flutter or Dart coverage missing in Docker
  This is expected in the default image. Use host mode or build a custom extended image if you need Flutter/Dart analysis inside containers.

## Authentication and Roles

- Local username/password login remains available for bootstrapping and fallback administration.
- OIDC login is optional and enabled only when `OIDC_ENABLED=true` plus issuer/client settings are configured.
- After either local login or OIDC login, the UI stays session-based.
- Roles:
  - `admin`: manage projects, submit scans, browse reports, and manage user roles
  - `reviewer`: submit scans and browse projects/scans/reports
- `viewer`: browse projects/scans/reports only
- OIDC roles are derived from a configurable claim such as `groups`, with environment-driven group-to-role mapping.

## Trend Visibility

- Project detail pages include a trend section derived only from stored scans in the same project.
- Each trend point shows severity totals, weighted risk score, policy result, and comparison-derived new/resolved/unchanged counts when a prior same-project scan exists.
- Weighted risk uses grouped findings with deterministic severity weights: `critical=5`, `high=4`, `medium=3`, `low=2`, `info=1`, `unknown=1`.
- Trend aggregation is project-level only in this milestone. Cross-project trends are intentionally excluded.

## Policy Presets

- Global environment settings remain the baseline when a project does not declare a policy preset or override.
- Built-in presets:
  - `strict`: fail at `high` or above, fail on any new critical, allow `0` new high findings, allow `0` weighted risk increase, warn on partial scans, warn when any high or critical findings remain
  - `balanced`: fail at `critical`, fail on any new critical, allow `0` new high findings, allow weighted risk increase up to `5`, warn on partial scans, warn when any high or critical findings remain
  - `advisory`: disable current-severity failures, disable new-critical failures, allow large comparison deltas, and keep warning-only behavior
- Project overrides can further refine:
  - fail severity threshold
  - max new high findings
  - max weighted risk delta
  - warn on partial scan
  - warn on any high findings
- Effective policy resolution order is:
  1. global env defaults
  2. project preset if configured
  3. project override fields if configured

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_NAME` | `Internal Security Audit Platform` | FastAPI title and UI name |
| `APP_ENV` | `development` | Environment label |
| `APP_DEBUG` | `true` | Debug mode toggle |
| `APP_HOST` | `0.0.0.0` | Host binding |
| `APP_PORT` | `8000` | Port binding |
| `SECRET_KEY` | `change-this-in-production` | Session signing key; change this in every non-dev deployment |
| `SESSION_COOKIE_SECURE` | `false` | Send session cookies only over HTTPS when enabled |
| `SESSION_MAX_AGE_SECONDS` | `28800` | Session lifetime in seconds |
| `BOOTSTRAP_ADMIN_USERNAME` | empty | Optional username for `scripts/bootstrap_admin.py` |
| `BOOTSTRAP_ADMIN_PASSWORD` | empty | Optional password for `scripts/bootstrap_admin.py` |
| `OIDC_ENABLED` | `false` | Enable OIDC/OAuth2 login |
| `OIDC_ISSUER_URL` | empty | OIDC issuer base URL used for discovery |
| `OIDC_CLIENT_ID` | empty | OIDC client identifier |
| `OIDC_CLIENT_SECRET` | empty | OIDC client secret |
| `OIDC_SCOPES` | `openid profile email` | Space-separated OIDC scopes |
| `OIDC_ROLE_CLAIM` | `groups` | Claim name used for role/group mapping |
| `OIDC_DEFAULT_ROLE` | `viewer` | Fallback role when no mapped group is present |
| `OIDC_ADMIN_GROUPS` | empty | Comma-separated OIDC groups that map to `admin` |
| `OIDC_REVIEWER_GROUPS` | empty | Comma-separated OIDC groups that map to `reviewer` |
| `OIDC_VIEWER_GROUPS` | empty | Comma-separated OIDC groups that map to `viewer` |
| `OIDC_USERNAME_CLAIM` | `preferred_username` | Claim used for local username provisioning |
| `OIDC_EMAIL_CLAIM` | `email` | Claim used for email provisioning |
| `OIDC_NAME_CLAIM` | `name` | Claim used for display-name provisioning |
| `DATABASE_URL` | `sqlite:///./db/security_audit.db` | Database connection string |
| `ALLOW_LOCAL_PATH_SCANS` | `true` | Enable local path scans |
| `ALLOW_ARCHIVE_UPLOADS` | `true` | Enable zip archive uploads |
| `SCAN_UPLOAD_DIR` | `uploads` | Uploaded archive storage |
| `SCAN_WORKSPACE_DIR` | `workspaces` | Extracted per-scan workspace root |
| `REPORT_OUTPUT_DIR` | `reports/generated` | Generated report output path |
| `SEMGREP_COMMAND` | `semgrep` | Semgrep executable name or absolute path |
| `SEMGREP_CONFIG` | `auto` | Semgrep rule configuration |
| `SEMGREP_TIMEOUT_SECONDS` | `300` | Semgrep execution timeout |
| `TRIVY_COMMAND` | `trivy` | Trivy executable name or absolute path |
| `TRIVY_TIMEOUT_SECONDS` | `300` | Trivy execution timeout |
| `PIP_AUDIT_COMMAND` | `pip-audit` | Python dependency audit executable or virtualenv path |
| `PIP_AUDIT_TIMEOUT_SECONDS` | `300` | `pip-audit` execution timeout |
| `NPM_COMMAND` | `npm` | Node dependency audit executable or absolute path |
| `NPM_AUDIT_TIMEOUT_SECONDS` | `300` | `npm audit` execution timeout |
| `FLUTTER_COMMAND` | `flutter` | Flutter SDK executable or absolute path used for Flutter-first analysis and `pub outdated` |
| `DART_COMMAND` | `dart` | Dart SDK executable or absolute path used for Dart analysis and `pub outdated` fallback |
| `DART_ANALYZE_TIMEOUT_SECONDS` | `300` | Dart/Flutter static analysis timeout |
| `DART_PUB_OUTDATED_TIMEOUT_SECONDS` | `300` | Dart/Flutter dependency freshness timeout |
| `JOB_POLL_INTERVAL_SECONDS` | `1` | In-process worker queue poll interval |
| `AI_ENABLED` | `false` | Enable optional AI enrichment after deterministic scanning completes |
| `AI_PROVIDER` | `disabled` | AI provider type: `disabled`, `ollama`, `openai`, or `openai_compatible` |
| `AI_MODEL` | `llama3.1:8b` | Model identifier sent to the provider |
| `AI_BASE_URL` | `http://127.0.0.1:11434/v1` | OpenAI-compatible base URL, including local Ollama gateways |
| `AI_API_KEY` | empty | Bearer token for remote or secured AI endpoints; often blank for local Ollama |
| `AI_TIMEOUT_SECONDS` | `30` | Timeout for AI completion calls |
| `API_TOKENS` | empty | Comma-separated bearer/service tokens for `/api/v1` routes |
| `ALLOW_API_LOCAL_PATH_SCANS` | `false` | Explicitly allow local path scans over the token API |
| `WEBHOOK_SHARED_SECRET` | empty | Shared secret for webhook intake routes |
| `CI_DEFAULT_FAIL_SEVERITY` | empty | Default severity threshold for current-scan fail policy; falls back to `critical` |
| `POLICY_FAIL_ON_NEW_CRITICAL` | `true` | Fail when a comparison shows any new critical findings |
| `POLICY_MAX_NEW_HIGH_FINDINGS` | `0` | Maximum allowed new high-severity findings before policy fails |
| `POLICY_MAX_WEIGHTED_RISK_DELTA` | `5` | Maximum allowed increase in weighted grouped risk score |
| `POLICY_WARN_ON_ANY_HIGH_FINDINGS` | `true` | Warn when the current scan still contains high or critical findings |
| `POLICY_WARN_ON_PARTIAL_SCAN` | `true` | Warn when the scan completed with partial tool coverage |
| `UPLOAD_RETENTION_DAYS` | `30` | Retention window for uploaded archive directories |
| `WORKSPACE_RETENTION_DAYS` | `30` | Retention window for extracted uploaded workspaces |
| `REPORT_RETENTION_DAYS` | `30` | Retention window for generated report files |
| `CLEANUP_INTERVAL_SECONDS` | `3600` | In-process cleanup interval |
| `CLEANUP_ON_STARTUP` | `true` | Run a cleanup pass during startup |

## Authentication Model

- The UI uses session-based authentication with one `admin` role.
- Passwords are stored as salted `pbkdf2_sha256` hashes through Passlib.
- Protected routes include dashboard, scan creation, scan detail, report downloads, and project management pages.
- `/health` remains unauthenticated for readiness checks.
- Forms include a session-backed CSRF token.
- The current model is intentionally small so SSO/OAuth and RBAC can replace or extend it later without rewriting scan services.

## API Access Model

- `/api/v1` routes use token auth only and do not reuse the browser session.
- Tokens are supplied through `Authorization: Bearer <token>` or `X-API-Token`.
- API tokens are read from `API_TOKENS` and are intended for CI jobs or internal service integrations.
- Local path scans over the API are disabled by default and require `ALLOW_API_LOCAL_PATH_SCANS=true`.
- Webhook routes use a separate `WEBHOOK_SHARED_SECRET`.

## AI Assistance

- AI is optional and disabled by default.
- The worker runs AI enrichment only after scanner findings are already persisted.
- A disabled or failed AI provider never marks the scan itself as failed.
- The current provider abstraction supports:
  - `disabled`: explicit no-op mode
  - `ollama`: OpenAI-compatible local HTTP endpoint
  - `openai_compatible`: generic chat-completions-compatible endpoint
- The AI layer uses normalized finding metadata, severity counts, tool names, and grouped finding summaries instead of sending large raw payloads by default.
- Findings can show AI explanation and AI remediation text.
- Scan detail pages and reports can show AI management summary, top risks, and next steps.
- Scan detail pages also show AI readiness and status as one of:
  - `Disabled`
  - `Enabled`
  - `Completed`
  - `Partial`
  - `Failed`
- AI text is always advisory. Deterministic findings, raw evidence, comparison, and policy remain authoritative.

### AI Setup Modes

Disabled/default mode:

```bash
AI_ENABLED=false
AI_PROVIDER=disabled
```

Local Ollama or another local OpenAI-compatible endpoint:

```bash
AI_ENABLED=true
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
AI_BASE_URL=http://127.0.0.1:11434/v1
AI_TIMEOUT_SECONDS=30
```

Hosted OpenAI-compatible endpoint:

```bash
AI_ENABLED=true
AI_PROVIDER=openai_compatible
AI_MODEL=gpt-4o-mini
AI_BASE_URL=https://your-gateway.example.com/v1
AI_API_KEY=replace-me
AI_TIMEOUT_SECONDS=30
```

Hosted OpenAI-style endpoint with required key:

```bash
AI_ENABLED=true
AI_PROVIDER=openai
AI_MODEL=gpt-4o-mini
AI_BASE_URL=https://api.openai.com/v1
AI_API_KEY=replace-me
AI_TIMEOUT_SECONDS=30
```

### AI Troubleshooting

- If AI is disabled, scans still run normally and all policy decisions still work.
- If AI is enabled but incomplete, the dashboard and scan detail page show configuration warnings and scans continue without reliable AI enrichment.
- If AI fails for a specific scan, the scan result still reflects deterministic scanner execution; only the AI advisory section is degraded.
- Use `python scripts/check_requirements.py --json` and review the `ai` section to confirm whether AI is disabled intentionally, misconfigured, or ready.

## Grouped Findings

- Grouping is a derived, non-destructive view over persisted raw findings.
- The grouping key uses normalized `title`, `severity`, `category`, `tool_name`, `file_path`, and dependency name when present.
- Grouped summaries show member counts, representative metadata, and affected files while leaving the underlying finding records available for drill-down and audit traceability.
- Scan-level AI summaries use grouped findings so repeated issues do not dominate the management summary.

## Scan Comparison

- Comparison is derived from stored scan data only; raw findings are never mutated.
- The comparison key reuses grouped finding identity, so severity or file-path changes intentionally show up as resolved-plus-new rather than fuzzy matches.
- The default comparison target is the nearest older scan from the same project.
- Comparison output shows new, resolved, and unchanged grouped findings plus severity and weighted-risk deltas.

## CI Policy Gates

- Policy evaluation is deterministic and derived from stored scan findings plus optional comparison data.
- The current policy layer supports:
  - fail if the current scan contains findings at or above the configured severity threshold
  - fail if any new critical findings were introduced
  - fail if new high-severity findings exceed the configured allowance
  - fail if weighted grouped risk increased beyond the configured allowance
  - warn when scans are partial or when high/critical findings remain
- If no previous scan exists, comparison-based rules are skipped cleanly instead of failing the scan.
- API summaries and reports expose `policy.status`, `policy.should_fail_ci`, triggered rules, and short reasons for CI/CD consumers.

## Supported Ecosystems

- Python: `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`, `Pipfile.lock`
- Node: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- Dart: `pubspec.yaml`, `pubspec.lock`, `analysis_options.yaml`
- Flutter: Flutter-style `pubspec.yaml` plus common platform markers such as `android/`, `ios/`, and `lib/`
- Maven: `pom.xml` and optional `.mvn/`
- Composer: `composer.json`, `composer.lock`
- Go: `go.mod`, `go.sum`
- .NET / NuGet: `*.csproj`, `*.sln`, `packages.lock.json`, `Directory.Packages.props`

## Flutter / Dart Coverage

- Dart projects are detected through `pubspec.yaml`, `pubspec.lock`, or `analysis_options.yaml`.
- Flutter projects are detected from Flutter-style `pubspec.yaml` content plus common platform markers such as `android/`, `ios/`, or `lib/`.
- Static analysis prefers `flutter analyze --no-pub` for Flutter projects and falls back to `dart analyze` for Dart projects.
- Dependency freshness uses `flutter pub outdated --json` or `dart pub outdated --json` without running `pub get` or building the app.
- `pub outdated` requires `pubspec.lock`; if the lockfile is missing, the dependency tool is skipped cleanly.
- The platform does not build Flutter apps, run project tests, or execute package scripts/hooks.

## Maven / Composer Coverage

- Maven projects are detected through `pom.xml` and optional `.mvn/` directories.
- Maven support is deterministic and manifest-driven through `maven-pom-review`; it does not run `mvn`, build the project, or resolve the full dependency graph.
- Maven findings currently cover floating versions such as `LATEST` or `RELEASE`, snapshot versions, insecure repository URLs, and system-scoped dependencies.
- Composer projects are detected through `composer.json` and `composer.lock`.
- Composer support is deterministic and manifest-driven through `composer-review`; it does not run `composer install`, `composer audit`, or execute PHP code.
- Composer findings currently cover insecure `secure-http` settings, wildcard `allow-plugins`, and abandoned packages recorded in `composer.lock`.

## Go / .NET Coverage

- Go projects are detected through `go.mod` and `go.sum`.
- Go support is deterministic and manifest-driven through `go-mod-review`; it does not run `go build`, `go test`, or fetch modules.
- Go findings currently cover local or overridden `replace` directives, unpinned `toolchain default`, and pseudo-version usage in `go.mod`.
- .NET / NuGet projects are detected through `*.csproj`, `*.sln`, `packages.lock.json`, and `Directory.Packages.props`.
- .NET support is deterministic and manifest-driven through `dotnet-project-review`; it does not run `dotnet restore`, `dotnet build`, or execute project code.
- .NET findings currently cover floating package versions, pre-release package versions, and insecure restore sources visible in project or central package files.

## Flutter Mobile Config Coverage

- Android checks currently inspect `android/app/src/main/AndroidManifest.xml` when present.
- iOS checks currently inspect `ios/Runner/Info.plist` when present.
- Android findings include first-pass checks for:
  - `usesCleartextTraffic=true`
  - `android:debuggable=true`
  - `android:allowBackup=true`
  - exported components marked `android:exported=true`
  - selected sensitive permissions such as camera, audio, SMS, contacts, phone state, and broad storage access
- iOS findings include first-pass checks for:
  - `NSAllowsArbitraryLoads`
  - `NSExceptionAllowsInsecureHTTPLoads`
  - `UIFileSharingEnabled`
- These checks are deterministic and file-based. They do not build the app, run Xcode/Gradle, or infer runtime behavior.

## Framework-Aware Coverage

- Spring detection is based on Maven manifests plus visible Spring Boot and config-file hints.
- Laravel detection is based on Composer dependencies plus common Laravel project structure and env/config files.
- Express detection is based on `package.json` dependencies plus common entrypoint files such as `app.js`, `server.js`, or `index.js`.
- Flutter deeper framework review builds on existing Flutter app detection plus `lib/*.dart` source files.
- Current framework-specific checks are deterministic and parser-only:
  - Spring: broad actuator exposure, dev profile defaults, broad bind-address hints
  - Laravel: `APP_DEBUG=true`, HTTP `APP_URL`, trust-all proxies
  - Express: global `trust proxy`, cookies with `httpOnly: false`, cookies with `secure: false`
  - Flutter app source: literal `http://` endpoints, high-confidence hardcoded secrets, sensitive logging patterns
- Framework findings use the same shared normalized model and flow through the existing grouping, comparison, policy, AI, report, UI, and API layers.
- These checks are intentionally conservative and do not fully interpret dynamic framework configuration or runtime behavior.

Example local AI configuration:

```bash
AI_ENABLED=true
AI_PROVIDER=ollama
AI_MODEL=llama3.1:8b
AI_BASE_URL=http://127.0.0.1:11434/v1
AI_TIMEOUT_SECONDS=30
```

Example remote OpenAI-compatible configuration:

```bash
AI_ENABLED=true
AI_PROVIDER=openai_compatible
AI_MODEL=gpt-4o-mini
AI_BASE_URL=https://your-gateway.example.com/v1
AI_API_KEY=replace-me
```

## CI / GitLab Integration

- The JSON API can enqueue scans with a zip upload, poll for completion, and download reports.
- A GitLab example is provided in [`docs/gitlab-ci.example.yml`](/Users/nm/Documents/GitHub/AI-Agent/docs/gitlab-ci.example.yml).
- API details and curl examples are documented in [`docs/api.md`](/Users/nm/Documents/GitHub/AI-Agent/docs/api.md).
- Scan summary APIs now include grouped finding summaries in addition to raw severity and tool counts.
- Comparison APIs now expose regression summaries suitable for CI or internal automation.
- Policy APIs now expose pass/fail/warn decisions suitable for CI job gating.

## Scanner Prerequisites

Milestone 20 integrates shared scanners plus ecosystem- and framework-specific adapters across Python, Node, Dart, Flutter, Maven, Composer, Go, .NET, Spring, Laravel, and Express.

- Local install example: `pip install semgrep` or install from Semgrep’s official packages
- Install Trivy from Aqua Security’s official packages or binary distribution
- Install `pip-audit` with `pip install pip-audit` if Python dependency auditing is desired
- Install `npm` if Node dependency auditing is desired
- Install the Flutter SDK if Flutter project analysis is desired
- Install the Dart SDK if Dart package analysis is desired or as a fallback where Flutter is not available
- Maven and Composer first-pass support is manifest-driven and does not require `mvn` or `composer`
- Go and .NET first-pass support is manifest-driven and does not require `go` or `dotnet`
- No Android SDK, Gradle, Xcode, or CocoaPods execution is required for the mobile config review checks
- `npm audit` expects a `package-lock.json` or `npm-shrinkwrap.json`; if only `package.json` is present, the tool is skipped with a recorded note
- Dart/Flutter dependency freshness expects `pubspec.lock`; if only `pubspec.yaml` is present, the tool is skipped with a recorded note
- If one tool is not installed, the platform still records the scan and marks the scan `partial`
- If no configured tools complete successfully, the scan is marked `failed`
- If no supported ecosystem manifests exist for a dependency tool, that tool is skipped cleanly
- Mixed repositories can run multiple ecosystem adapters in the same scan when their audit-ready manifests are present

Dependency audits, richer secret scanning, and GitLab CI packaging are planned next.

## Job Lifecycle

- `POST /scans` validates input, prepares the workspace, creates a `queued` scan record, and enqueues the scan ID.
- `POST /api/v1/scans` reuses the same enqueue path for external systems and returns quickly with JSON.
- The in-process worker thread updates the scan to `running`, executes scanners, persists findings/tool executions, and generates reports.
- The worker then optionally enriches the persisted findings/scan metadata through the AI service layer.
- The same worker also runs conservative cleanup passes for expired managed artifacts.
- Final scan states are `completed`, `partial`, or `failed`.
- On startup, the worker re-enqueues `queued` scans and marks previously `running` scans as `failed` with an interruption message.

## Retention and Cleanup

- Cleanup only targets files and directories under the managed upload, workspace, and report roots.
- Cleanup never deletes queued or running scan artifacts.
- Cleanup never deletes local-path repositories or database scan history by default.
- Separate retention windows apply to uploaded archives, extracted uploaded workspaces, and generated reports.
- Worker health, storage counts, and last cleanup summary are visible on the dashboard and `/api/v1/worker/status`.
- The cleanup loop is in-process and therefore best suited to a single app instance.

## Project Management

- Admins can create, view, and edit projects under `/projects`.
- A scan can target an existing project or create/infer one during submission.
- Project detail pages show recent scans and keep project metadata separate from scanner execution state.

## Tests

```bash
pytest
```

## Roadmap

- Phase 1: initial scanning MVP, normalization, reports, Docker runtime
- Phase 2: auth, multiple projects, audit history refinement, better filtering
- Phase 3: AI explanations, remediation suggestions, management summaries, and grouping
- Phase 4: GitLab CI integration pack, API/webhook triggers, build thresholds, and broader ecosystem coverage
- Phase 5: Dart/Flutter ecosystem support and future mobile-specific checks
- Phase 5: broader ecosystem coverage for Maven, Composer, and future adapters such as Go or .NET
- Phase 5: broader ecosystem coverage for Go, .NET, and future adapters such as Ruby or Rust
- Phase 5: operational cleanup controls, worker visibility, and grouped finding review ergonomics
- Phase 5: scan-to-scan comparison, regression tracking, and future trend dashboards
- Phase 5: RBAC, notifications, PDF export, deeper integrations

## Current Limitations

- Background execution is in-process and intended for a single app instance
- Uploaded workspaces remain on disk until retention cleanup removes managed artifacts
- SQLite default for developer convenience
- One local admin role only; no SSO, MFA, or full RBAC yet
- No GitLab pipeline execution yet
- Python dependency audits currently rely on requirements-style files for `pip-audit`
- Node dependency audits currently rely on `package-lock.json` or `npm-shrinkwrap.json` for `npm audit`
- Dart/Flutter dependency freshness currently relies on `pubspec.lock` for `pub outdated`
- Maven support is first-pass and manifest-driven; it does not resolve full dependency graphs or run Maven plugins
- Composer support is first-pass and manifest-driven; it does not install dependencies or run `composer audit`
- Go support is first-pass and manifest-driven; it does not resolve full module graphs or evaluate module provenance beyond file-based signals
- .NET support is first-pass and manifest-driven; it does not restore packages or inspect full NuGet configuration beyond project-visible settings
- Flutter static analysis and mobile config review are first-pass checks and do not yet cover deeper AndroidManifest.xml/Info.plist policy validation, entitlements, or platform build settings
- AI prompting is intentionally compact and may omit edge-case context
- Finding grouping is deterministic and conservative; it does not attempt fuzzy semantic clustering
- Scan comparison is deterministic and same-project only; it does not attempt fuzzy matching across renamed issues
- Policy evaluation is global and env-driven in this milestone; per-project policy customization is not implemented yet
- Remote AI providers may transmit repository-derived metadata outside the environment if configured
- API tokens are env-driven and coarse-grained; there is no per-token scope model yet
- Cleanup is in-process and not coordinated across multiple app replicas
