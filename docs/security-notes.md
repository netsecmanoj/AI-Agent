# Security Notes

## Milestone 9 Defaults

- Local path scanning is enabled for operator convenience.
- Zip archive uploads are accepted when `ALLOW_ARCHIVE_UPLOADS=true`.
- Session-based admin authentication protects dashboard, scan, report, and project routes.
- Optional OIDC login can provision local session users from trusted identity claims.
- `/api/v1` routes require a bearer or service token from `API_TOKENS`.
- Webhook routes require `WEBHOOK_SHARED_SECRET`.
- Scanner execution runs on an in-process background worker thread inside the app process.
- Cleanup also runs in-process on startup and at the configured interval.
- AI enrichment is disabled by default and runs only when `AI_ENABLED=true`.
- Grouped findings are computed from normalized findings and do not replace raw evidence.
- Scan comparisons are computed from stored grouped findings and do not mutate persisted scan data.
- Project-level trends are computed from stored scan history and do not mutate persisted scan data.
- Policy evaluation is deterministic, derived from stored findings/comparison data, and does not use AI.
- Project policies can layer deterministic presets and override fields on top of global defaults.
- Reports are stored on local disk.
- Uploaded archives are stored on local disk and extracted into per-scan workspaces.
- Passwords are stored as salted `pbkdf2_sha256` hashes through Passlib.
- Forms use a session-backed CSRF token.

## Operational Guidance

- Keep the service on an internal trusted network and terminate TLS at the reverse proxy.
- For Ubuntu host deployments, use the example systemd unit and Nginx config under `deploy/` rather than exposing uvicorn directly on the public network.
- Prefer a dedicated service account with restricted filesystem access.
- Mount only the repositories or directories that should be scanned.
- Do not mount directories containing sensitive host data that should never be scanned.
- Change `SECRET_KEY` before enabling real use.
- Set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- Rotate `API_TOKENS` and `WEBHOOK_SHARED_SECRET` through your secret-management workflow.
- Keep `ALLOW_API_LOCAL_PATH_SCANS=false` unless you explicitly trust the API caller's filesystem contract.
- Review retention settings before shortening artifact lifetimes.
- Bootstrap the first admin user with `scripts/bootstrap_admin.py` and deliver credentials out-of-band.
- If OIDC is enabled, map only trusted internal groups into application roles and keep at least one local fallback admin account.
- Only admins should edit project policy settings; reviewers and viewers should treat effective policy as read-only context.
- Use PostgreSQL for shared or multi-user deployments.
- Keep Semgrep rules/configuration under source control when the ruleset becomes customized.
- Install Trivy from trusted internal package sources or pinned vendor releases.
- Install `pip-audit` from trusted internal package sources if Python dependency auditing is enabled.
- Install `npm` from trusted internal package sources if Node dependency auditing is enabled.
- Install Flutter and Dart SDKs from trusted internal package sources if mobile or Dart analysis is enabled.
- Maven and Composer first-pass support in this milestone is manifest-driven and does not require `mvn` or `composer`.
- Go and .NET first-pass support in this milestone is manifest-driven and does not require `go` or `dotnet`.
- Run a single app instance for this milestone; the in-process queue is not designed for multi-instance coordination.
- Prefer local AI endpoints for sensitive repositories.
- Treat host-mode absolute command paths in `.env` as deployment-specific operator settings and keep them out of version control.
- If a remote AI provider is configured, treat normalized finding metadata as data leaving the environment.

## Upload and Extraction Protections

- Uploaded archives are restricted to `.zip`.
- Archive extraction rejects absolute paths and traversal entries such as `../../etc/passwd`.
- Scanners run only against the prepared workspace path, not arbitrary user-provided extraction targets.
- The service does not execute code inside the uploaded project; it only invokes approved scanner binaries against the workspace.

## Partial Scan Behavior

- Missing scanner binaries produce per-tool `skipped` executions and a scan-level `partial` status when at least one tool completes.
- Inapplicable dependency tools, such as `pip-audit` on non-Python projects, are skipped without forcing a `partial` scan.
- `npm audit` is skipped cleanly when a Node workspace has no `package-lock.json` or `npm-shrinkwrap.json`.
- `dart pub outdated` is skipped cleanly when a Dart or Flutter workspace has no `pubspec.lock`.
- Flutter/Dart analysis is skipped cleanly when no Dart or Flutter markers are present.
- Flutter mobile config review is skipped cleanly when `AndroidManifest.xml` and `Info.plist` are absent.
- Maven `pom.xml` review is skipped cleanly when no Maven manifest is present.
- Composer manifest review is skipped cleanly when no Composer manifest is present.
- Go module review is skipped cleanly when no `go.mod` manifest is present.
- .NET project review is skipped cleanly when no `*.csproj` or related .NET manifest is present.
- Tool failures and timeouts are recorded per execution and surfaced on the scan detail page.
- If no configured scanner completes successfully, the overall scan is marked `failed`.
- On startup, `queued` scans are re-enqueued and interrupted `running` scans are marked `failed` with a worker interruption message.
- AI enrichment failures do not change scan success/failure; they are recorded separately in AI status/error fields.
- Operator-facing readiness checks also report whether AI is intentionally disabled, incomplete, ready, or using an unsupported provider.
- Grouping is deterministic and conservative; it does not delete or merge raw persisted findings.
- Comparison is deterministic and same-project only; it does not rely on fuzzy or AI-based matching.
- Policy evaluation skips comparison-based rules when no older scan exists instead of inventing synthetic baselines.
- Project trend points show comparison-derived deltas only when a previous same-project comparable scan exists.
- Effective project policy is resolved deterministically from global defaults, then project preset, then project overrides.

## Authentication and RBAC Notes

- `/health` remains unauthenticated for readiness checks.
- The UI stays session-based after both local login and OIDC login.
- Local bootstrap authentication remains available even when OIDC is enabled.
- Roles are currently coarse-grained:
  - `admin`: project management, scan submission, report access, and user-role management
  - `reviewer`: scan submission plus project/scan/report browsing
  - `viewer`: project/scan/report browsing only
- OIDC role mapping is deterministic and environment-driven from a single claim such as `groups`.
- Future project-scoped RBAC or directory group-sync can extend the current model without changing scan persistence.

## Cleanup Safety Notes

- Cleanup only targets the configured managed roots for uploads, extracted uploaded workspaces, and generated reports.
- Cleanup does not delete database scan history by default.
- Cleanup never targets queued or running scans.
- Cleanup never deletes local-path repositories outside the managed workspace root.
- Missing artifact paths are tolerated without failing the worker.

## API and Webhook Notes

- Token-authenticated API routes are intended for CI jobs and internal services, not browser use.
- API upload is the preferred CI path because it avoids exposing host filesystem paths to callers.
- Local path API or webhook scans should only be enabled in tightly controlled internal environments.
- The webhook route currently validates the token and can enqueue a trusted local-path scan, but it does not fetch repository archives from SCM events yet.
- CI policy decisions are available from scan summaries and the dedicated policy endpoint so pipelines do not need to re-implement policy logic.

## AI Privacy Notes

- The AI layer uses normalized finding metadata and scan summaries rather than full raw findings payloads by default.
- Scan-level AI summaries use grouped findings so repeated issues are summarized once with count and affected-area context.
- When a previous scan exists, AI scan summaries can also receive bounded comparison metadata such as regression trend and severity deltas.
- Local/self-hosted AI providers are preferred for confidential repositories and infrastructure code.
- Remote providers may still receive file paths, issue titles, severities, categories, and remediation context when enabled.
- Do not point the platform at an external AI endpoint unless that data flow is acceptable for your organization.
- `AI_API_KEY` must be supplied through environment configuration, not committed to the repository.
- AI should be treated as explanatory only; pass/fail policy decisions remain deterministic and never depend on AI output.

## Supported Ecosystems

- Python projects are detected via `requirements.txt`, `requirements-dev.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile`, or `Pipfile.lock`.
- Node projects are detected via `package.json`, `package-lock.json`, or `npm-shrinkwrap.json`.
- Dart projects are detected via `pubspec.yaml`, `pubspec.lock`, or `analysis_options.yaml`.
- Flutter projects are detected via Flutter-style `pubspec.yaml` content plus common platform markers such as `android/`, `ios/`, and `lib/`.
- Maven projects are detected via `pom.xml` and optional `.mvn/` directories.
- Composer projects are detected via `composer.json` and `composer.lock`.
- Go projects are detected via `go.mod` and `go.sum`.
- .NET projects are detected via `*.csproj`, `*.sln`, `packages.lock.json`, and `Directory.Packages.props`.
- Python dependency auditing uses `pip-audit` against requirements-style manifests when available.
- Node dependency auditing uses `npm audit` when `package-lock.json` or `npm-shrinkwrap.json` is present.
- Flutter static analysis uses `flutter analyze --no-pub` when Flutter is available and falls back to `dart analyze` for Dart-only projects.
- Dart/Flutter dependency freshness uses `flutter pub outdated --json` or `dart pub outdated --json` when `pubspec.lock` is present.
- Flutter mobile posture checks inspect `android/app/src/main/AndroidManifest.xml` and `ios/Runner/Info.plist` when present.
- Framework review inspects Spring config files, Laravel env/config structure, Express entrypoint files, and Flutter app Dart source files when those framework hints are detected.
- Maven review inspects `pom.xml` files for floating or snapshot versions, insecure repository URLs, and system-scoped dependencies.
- Composer review inspects `composer.json` and `composer.lock` for insecure config and abandoned packages.
- Go review inspects `go.mod` for replace directives, pseudo-versions, and toolchain configuration signals.
- .NET review inspects `.csproj` and central package files for floating versions, pre-release packages, and insecure restore sources.
- Mixed repositories can trigger multiple ecosystem adapters in one scan when their audit-ready manifests are present.
- Unsupported or non-applicable ecosystems are skipped cleanly and remain traceable in tool execution records.

## Known Gaps

- No sandboxing of scanner execution
- Upload validation is limited to `.zip` type checks and safe extraction
- No audit log trail for user role changes yet
- No container/image scanning in this milestone
- The async model is single-process and not safe for horizontally scaled web replicas
- Cleanup scheduling is also single-process and not coordinated across multiple replicas
- AI prompting is summary-based and may miss project-specific business context
- Grouping does not yet do fuzzy semantic matching across differently titled findings
- Comparison keys are intentionally strict, so renamed findings appear as resolved plus new
- API tokens are coarse-grained and do not yet support per-project or per-route scopes
- OIDC provider discovery and token exchange are synchronous request-time calls in this milestone
- Trend aggregation is project-level only and does not provide cross-project rollups yet
- Project policy presets are intentionally small and built-in; there is no custom policy DSL yet
- Monorepo handling is still shallow; the scanner focuses on simple manifest discovery rather than full workspace graph analysis
- Flutter mobile posture coverage is first-pass only and does not yet inspect manifest variants, iOS entitlements, Android network security config XML, or platform build settings
- Framework-aware review is first-pass only and does not fully interpret dynamic framework configuration, environment inheritance, or runtime middleware behavior
- Maven support is first-pass only and does not resolve full dependency graphs, execute Maven plugins, or distinguish all Java frameworks
- Composer support is first-pass only and does not install dependencies or call `composer audit`
- Go support is first-pass only and does not resolve full module graphs, fetch modules, or inspect runtime code paths
- .NET support is first-pass only and does not run `dotnet restore`, inspect full NuGet.Config inheritance, or evaluate project runtime behavior
