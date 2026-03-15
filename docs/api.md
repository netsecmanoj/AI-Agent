# API Usage

## Authentication

- All `/api/v1` routes require a token from `API_TOKENS`.
- Send the token as `Authorization: Bearer <token>` or `X-API-Token: <token>`.
- Webhook routes use `WEBHOOK_SHARED_SECRET` instead.

## Endpoints

- `POST /api/v1/scans`
  Enqueue a scan from a zip upload or, when explicitly enabled, a local path.
- `GET /api/v1/scans/{scan_id}/status`
  Poll scan lifecycle state.
- `GET /api/v1/scans/{scan_id}`
  Fetch a stable JSON scan summary.
- `GET /api/v1/scans/{scan_id}/comparison`
  Fetch a deterministic comparison against the previous scan or a selected older scan.
- `GET /api/v1/scans/{scan_id}/policy`
  Fetch deterministic CI policy evaluation for one scan.
- `GET /api/v1/projects/{project_id}/scans`
  List recent scans for one project.
- `GET /api/v1/projects/{project_id}/trends`
  Fetch deterministic project-level trend summaries across stored scan history.
- `GET /api/v1/scans/{scan_id}/reports/{format}`
  Download `json` or `html` report artifacts.
- `GET /api/v1/worker/status`
  Return worker running state, queue depth, retention settings, storage counts, and last cleanup summary.
- `GET /api/v1/requirements/status`
  Return scanner/tool availability, AI readiness, invalid-path warnings, and expected coverage impact.
- `POST /api/v1/webhooks/gitlab`
  Validate a webhook token and optionally enqueue a trusted local-path scan.

## Curl Examples

Create a scan from a zip archive:

```bash
zip -r repo.zip .
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
  -F "project_name=my-service" \
  -F "source_label=${CI_COMMIT_REF_NAME:-manual}" \
  -F "archive_file=@repo.zip;type=application/zip" \
  http://127.0.0.1:8000/api/v1/scans
```

Poll scan status:

```bash
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/scans/${SCAN_ID}/status
```

Download JSON report:

```bash
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
  -o report.json \
  http://127.0.0.1:8000/api/v1/scans/${SCAN_ID}/reports/json
```

Fetch a comparison summary:

```bash
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
"http://127.0.0.1:8000/api/v1/scans/${SCAN_ID}/comparison"
```

Fetch a project trend summary:

```bash
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
  "http://127.0.0.1:8000/api/v1/projects/${PROJECT_ID}/trends"
```

Fetch scanner/tool availability:

```bash
curl -sS \
  -H "Authorization: Bearer ${AUDIT_API_TOKEN}" \
  http://127.0.0.1:8000/api/v1/requirements/status
```

## Polling Flow

1. Upload a zip archive to `POST /api/v1/scans`.
2. Read `scan.scan_id` from the JSON response.
3. Poll `GET /api/v1/scans/{scan_id}/status` until the status is not `queued` or `running`.
4. Fetch `GET /api/v1/scans/{scan_id}` for final summary or download the report artifact.
5. Apply your CI severity threshold to `severity_counts`.

The JSON scan summary includes:

- `scan_id`
- `status`
- `project`
- `source_type`
- `source_label`
- `ecosystems`
- `ecosystem_summary`
- `frameworks`
- `framework_summary`
- `severity_counts`
- `tool_summary`
- `grouped_finding_count`
- `repeated_group_count`
- `grouped_findings`
- `ai_summary`
- `policy`
- `report_urls`

Grouped findings are derived summaries. Raw findings remain available in the downloadable report artifacts.

`ecosystem_summary` is shared across all supported ecosystems and currently covers Python, Node, Dart, Flutter, Maven, Composer, Go, and .NET. Each entry includes detected manifests, audit-ready files, a simple `project_kind`, and marker hints used to select ecosystem-specific adapters.

`framework_summary` is additive and currently covers deterministic framework hints for Spring, Laravel, Express, and Flutter app source/config review. Each entry includes the file hints and markers that caused the shared `framework-review` adapter to run.

Comparison payloads include:

- `comparison_available`
- `trend`
- `summary`
- `severity_deltas`
- `grouped_delta`
- `new_groups`
- `resolved_groups`
- `unchanged_groups`

Policy payloads include:

- `status`
- `decision_ready`
- `should_fail_ci`
- `comparison_available`
- `reasons`
- `rules`
- `config`
- `metrics`

`policy.config` includes the effective project policy with:

- `preset`
- `source`
- `overrides`
- `fail_severity_threshold`
- `fail_on_new_critical`
- `max_new_high_findings`
- `max_weighted_risk_delta`
- `warn_on_any_high_findings`
- `warn_on_partial_scan`

Project trend payloads include:

- `project`
- `effective_policy`
- `total_scans`
- `comparison_points`
- `latest_weighted_risk_score`
- `latest_policy_status`
- `latest_severity_counts`
- `policy_counts`
- `message`
- `points`

Requirements payloads include:

- `all_available`
- `counts`
- `summary_text`
- `warnings`
- `tools`
- `ai`

The `ai` section includes:

- `status`
- `status_label`
- `status_tone`
- `enabled`
- `show_setup_hint`
- `setup_hint`
- `examples`
- `provider`
- `model`
- `base_url`
- `api_key_configured`
- `missing_fields`
- `summary_text`
- `warnings`

Each trend point includes:

- `scan_id`
- `created_at`
- `status`
- `source_type`
- `source_label`
- `total_findings`
- `severity_counts`
- `weighted_risk_score`
- `policy_status`
- `comparison_available`
- `comparison_trend`
- `new_group_count`
- `resolved_group_count`
- `unchanged_group_count`
- `weighted_risk_delta`

## Local Path API Risk

- `ALLOW_API_LOCAL_PATH_SCANS` is `false` by default.
- Enable it only for trusted internal deployments where the API caller and the scan host share an intentional filesystem contract.
- Prefer archive upload for CI systems.

## Webhook Notes

- The webhook route is intentionally small and validation-focused in this milestone.
- It supports a shared secret through `X-Webhook-Token` or `X-Gitlab-Token`.
- Automatic repository fetching from webhook metadata is not implemented yet.
- For GitLab CI, the recommended path is still archive upload from the runner job.

## Comparison Notes

- Comparisons are supported only between scans from the same project.
- The default comparison target is the nearest older scan.
- You can pass `compare_to=<scan_id>` to compare against another older scan from the same project.
- Matching is deterministic and reuses grouped finding identity; renamed findings are treated as resolved plus new.

## Trend Notes

- Trend summaries are project-level only in this milestone.
- Weighted risk uses grouped findings with deterministic severity weights: `critical=5`, `high=4`, `medium=3`, `low=2`, `info=1`, `unknown=1`.
- New, resolved, and unchanged counts are reused from the same deterministic comparison model used on scan detail pages.
- If a project has only one scan, trend points still exist, but comparison-derived fields remain unavailable until a later scan exists.

## Policy Notes

- Policy is deterministic and does not use AI.
- Current rules evaluate current severity thresholds, new critical findings, new high-severity thresholds, weighted risk delta, partial scan warnings, and remaining high/critical warnings.
- If no previous scan exists, comparison-dependent rules are reported as skipped rather than failed.
- The default severity threshold comes from `CI_DEFAULT_FAIL_SEVERITY` and falls back to `critical`.
- Effective policy resolution order is global env defaults, then project preset, then project overrides.
- Built-in presets are `strict`, `balanced`, and `advisory`.

## Flutter / Dart Notes

- Dart and Flutter ecosystem details are surfaced through `ecosystem_summary`.
- Flutter projects prefer `flutter analyze --no-pub` and `flutter pub outdated --json`.
- Dart projects use `dart analyze` and `dart pub outdated --json`.
- Dependency freshness requires `pubspec.lock`; the platform does not run `pub get` automatically.
- Flutter app scans may also emit `mobile_config`, `mobile_network_security`, `mobile_permissions`, and `mobile_debug_configuration` findings from Android and iOS file review.

## Maven / Composer Notes

- Maven projects are detected from `pom.xml` and optional `.mvn/` directories.
- First-pass Maven support is manifest-driven through `maven-pom-review`; it does not run `mvn`, build the project, or resolve the full dependency graph.
- Maven findings can include `dependency_risk` and `build_configuration` categories for floating versions, snapshot usage, insecure repositories, and system-scoped dependencies.
- Composer projects are detected from `composer.json` and `composer.lock`.
- First-pass Composer support is manifest-driven through `composer-review`; it does not run `composer install` or execute PHP code.
- Composer findings can include `dependency_risk` and `build_configuration` categories for abandoned packages and insecure config such as `secure-http=false`.

## Go / .NET Notes

- Go projects are detected from `go.mod` and `go.sum`.
- First-pass Go support is manifest-driven through `go-mod-review`; it does not run `go build`, `go test`, or fetch modules.
- Go findings can include `dependency_risk`, `build_configuration`, and `module_configuration` categories for replace directives, pseudo-versions, and toolchain configuration signals.
- .NET / NuGet projects are detected from `*.csproj`, `*.sln`, `packages.lock.json`, and `Directory.Packages.props`.
- First-pass .NET support is manifest-driven through `dotnet-project-review`; it does not run `dotnet restore`, build the project, or execute project code.
- .NET findings can include `dependency_risk`, `build_configuration`, and `package_configuration` categories for floating versions, pre-release packages, and insecure restore sources.

## Framework Review Notes

- Framework-aware review is additive to ecosystem detection and does not replace generic scanners such as Semgrep or Trivy.
- Spring checks currently cover broad actuator exposure, dev-profile defaults, and broad bind-address hints visible in committed config files.
- Laravel checks currently cover `APP_DEBUG=true`, HTTP `APP_URL`, and trust-all proxy configuration when visible in committed files.
- Express checks currently cover global `trust proxy`, cookies with `httpOnly: false`, and cookies with `secure: false` in common entrypoint files.
- Flutter app source checks currently cover literal `http://` endpoints, high-confidence hardcoded secrets, and sensitive logging patterns in `lib/*.dart`.
- Framework review is parser-only and does not execute framework code, build the project, or try to resolve dynamic runtime configuration.
