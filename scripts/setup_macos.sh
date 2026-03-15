#!/usr/bin/env bash
set -euo pipefail

echo "macOS host setup for the Internal Security Audit Platform"
echo
echo "This script installs the practical baseline scanner tools for host-mode use:"
echo "  - semgrep"
echo "  - trivy"
echo "  - node (npm)"
echo
echo "It does not install Flutter or Dart automatically."
echo "Flutter/Dart remain optional and should be installed separately if you want Dart/Flutter coverage."
echo

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required for this helper."
  echo "Install Homebrew first: https://brew.sh/"
  exit 1
fi

echo "Installing Homebrew packages..."
brew install semgrep trivy node

if [[ -x ".venv/bin/pip" ]]; then
  echo
  echo "Installing pip-audit into the project virtual environment..."
  .venv/bin/pip install pip-audit
else
  echo
  echo "No project virtual environment found at .venv."
  echo "Create it first, then install Python requirements and pip-audit:"
  echo "  python3 -m venv .venv"
  echo "  . .venv/bin/activate"
  echo "  pip install -r requirements.txt"
  echo "  pip install pip-audit"
fi

echo
echo "Next steps:"
echo "  1. Copy .env.example to .env"
echo "  2. Adjust scanner command paths in .env if your tools are not on PATH"
echo "  3. Run: python scripts/check_requirements.py"
echo "  4. Bootstrap an admin: python scripts/bootstrap_admin.py --username admin --password 'change-me-now'"
