#!/usr/bin/env bash
# Runs govulncheck and fails only on symbol-level findings that are not
# accepted in .govulncheck-allow. Run from the module directory to scan.
set -euo pipefail

allowlist="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.govulncheck-allow"

report=$(mktemp)
findings=$(mktemp)
trap 'rm -f "$report" "$findings"' EXIT

govulncheck -format json ./... >"$report"

jq -rs '[.[] | select(.finding) | .finding
        | select(.trace[0].function != null) | .osv] | unique | .[]' \
  "$report" >"$findings"

allowed=$(grep -vE '^\s*(#|$)' "$allowlist" | sort -u)
unexpected=$(comm -23 <(sort -u "$findings") <(echo "$allowed"))

if [ -n "$unexpected" ]; then
  echo "Unaccepted symbol-level vulnerabilities:"
  echo "$unexpected" | sed 's/^/  /'
  echo
  echo "Fix them, or add the ID to .govulncheck-allow with a rationale."
  govulncheck ./... || true
  exit 1
fi

echo "No unaccepted symbol-level vulnerabilities."
echo "Accepted (see .govulncheck-allow):"
sort -u "$findings" | sed 's/^/  /'
