#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_NGINX=0

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/setup_ubuntu.sh [--with-nginx]

Installs baseline host dependencies for the Internal Security Audit Platform on Ubuntu:
  - python3
  - python3-venv
  - python3-pip
  - git
  - curl
  - unzip
  - nodejs / npm
  - trivy

Then creates the project virtualenv and installs:
  - Python app requirements
  - semgrep
  - pip-audit

Flutter/Dart remain optional and are not installed by this script.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-nginx)
      WITH_NGINX=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run with sudo so apt packages can be installed." >&2
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Cannot detect operating system. This script expects Ubuntu." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" ]]; then
  echo "This script currently supports Ubuntu host setup only." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

PACKAGES=(
  python3
  python3-venv
  python3-pip
  git
  curl
  unzip
  ca-certificates
  gnupg
  lsb-release
  nodejs
  npm
)

if [[ ${WITH_NGINX} -eq 1 ]]; then
  PACKAGES+=(nginx)
fi

echo "==> Installing Ubuntu host packages"
apt-get update
apt-get install -y --no-install-recommends "${PACKAGES[@]}"

echo "==> Installing Trivy apt repository"
install -d -m 0755 /usr/share/keyrings
curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
  | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
  > /etc/apt/sources.list.d/trivy.list
apt-get update
apt-get install -y --no-install-recommends trivy

echo "==> Preparing project virtual environment"
python3 -m venv "${ROOT_DIR}/.venv"
"${ROOT_DIR}/.venv/bin/pip" install --upgrade pip
"${ROOT_DIR}/.venv/bin/pip" install -r "${ROOT_DIR}/requirements.txt"
"${ROOT_DIR}/.venv/bin/pip" install semgrep pip-audit

if [[ ! -f "${ROOT_DIR}/.env" ]]; then
  cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
  echo "==> Created ${ROOT_DIR}/.env from .env.example"
fi

echo
echo "Ubuntu host setup complete."
echo
echo "Recommended .env command overrides for host mode:"
echo "  SEMGREP_COMMAND=${ROOT_DIR}/.venv/bin/semgrep"
echo "  PIP_AUDIT_COMMAND=${ROOT_DIR}/.venv/bin/pip-audit"
echo "  TRIVY_COMMAND=trivy"
echo "  NPM_COMMAND=npm"
echo
echo "Flutter/Dart remain optional. Install them separately if you need Flutter/Dart analysis."
echo
echo "Next steps:"
echo "  1. Review ${ROOT_DIR}/.env"
echo "  2. Run ${ROOT_DIR}/.venv/bin/python ${ROOT_DIR}/scripts/check_requirements.py"
echo "  3. Bootstrap admin: ${ROOT_DIR}/.venv/bin/python ${ROOT_DIR}/scripts/bootstrap_admin.py --username admin --password 'change-me-now'"
echo "  4. Start uvicorn or use the systemd example under deploy/systemd/"
