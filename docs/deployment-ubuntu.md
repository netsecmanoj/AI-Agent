# Ubuntu Host Deployment

This guide assumes an Ubuntu host or EC2 instance and keeps the platform in host mode so scanner binaries and local paths are easy to manage.

## What installs automatically

The helper script [`scripts/setup_ubuntu.sh`](/Users/nm/Documents/GitHub/AI-Agent/scripts/setup_ubuntu.sh) installs:

- `python3`
- `python3-venv`
- `python3-pip`
- `git`
- `curl`
- `unzip`
- `nodejs`
- `npm`
- `trivy`
- the project virtualenv
- Python app requirements
- `semgrep` in the project virtualenv
- `pip-audit` in the project virtualenv

Optional with `--with-nginx`:

- `nginx`

Not installed automatically:

- Flutter
- Dart

Those remain optional and should only be installed when Flutter/Dart analysis is required.

## Recommended host layout

Example application directory:

```bash
/opt/internal-security-audit
```

Recommended steps:

```bash
git clone https://github.com/netsecmanoj/AI-Agent.git /opt/internal-security-audit
cd /opt/internal-security-audit
sudo ./scripts/setup_ubuntu.sh --with-nginx
cp .env.example .env
```

Then set host-mode command overrides in `.env`:

```bash
SEMGREP_COMMAND=/opt/internal-security-audit/.venv/bin/semgrep
PIP_AUDIT_COMMAND=/opt/internal-security-audit/.venv/bin/pip-audit
TRIVY_COMMAND=trivy
NPM_COMMAND=npm
```

Add Flutter/Dart only if needed:

```bash
FLUTTER_COMMAND=/opt/flutter/bin/flutter
DART_COMMAND=/opt/flutter/bin/dart
```

## Verify before starting

Run the operator preflight:

```bash
/opt/internal-security-audit/.venv/bin/python /opt/internal-security-audit/scripts/check_requirements.py
/opt/internal-security-audit/.venv/bin/python /opt/internal-security-audit/scripts/check_requirements.py --json
```

The check reports:

- available tools
- missing tools
- invalid configured paths
- affected scanner coverage
- AI readiness

## systemd

An example unit file is provided at [`deploy/systemd/internal-security-audit.service`](/Users/nm/Documents/GitHub/AI-Agent/deploy/systemd/internal-security-audit.service).

Copy and adjust the paths for your install:

```bash
sudo cp deploy/systemd/internal-security-audit.service /etc/systemd/system/internal-security-audit.service
sudo systemctl daemon-reload
sudo systemctl enable --now internal-security-audit
sudo systemctl status internal-security-audit
```

The example unit runs:

- `ExecStartPre`: non-strict preflight JSON output for startup visibility
- `ExecStart`: `uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`

## Nginx

An example reverse-proxy config is provided at [`deploy/nginx/internal-security-audit.conf`](/Users/nm/Documents/GitHub/AI-Agent/deploy/nginx/internal-security-audit.conf).

Typical activation:

```bash
sudo cp deploy/nginx/internal-security-audit.conf /etc/nginx/sites-available/internal-security-audit
sudo ln -s /etc/nginx/sites-available/internal-security-audit /etc/nginx/sites-enabled/internal-security-audit
sudo nginx -t
sudo systemctl reload nginx
```

## Health and operator checks

Verify the service:

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/v1/worker/status
curl -fsS -H "Authorization: Bearer <token>" http://127.0.0.1:8000/api/v1/requirements/status
```

The dashboard also shows:

- scanner/tool requirement status
- AI readiness
- worker status
- storage/cleanup state

## Host mode vs container mode

- Host mode:
  - best for absolute tool-path control
  - recommended when Flutter/Dart scanning matters
  - easiest for local filesystem scans on one host
- Container mode:
  - easier to reproduce
  - baseline scanners already bundled
  - Flutter/Dart still optional and external by default
