#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPORT_PATH="$SCRIPT_DIR/ca9-vet.json"

cd "$SCRIPT_DIR" || exit 1

python3 make_demo.py

export PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
export CA9_ARTIFACT_CACHE_DIR="$SCRIPT_DIR/.ca9-artifact-cache"

CMD=(
  python3 -m ca9.cli vet
  --repo "$SCRIPT_DIR/repo"
  --scan-artifacts
  --internal-package "acme-*"
  --private-index "https://packages.acme.internal/simple"
  --deny-license "AGPL-3.0"
)

echo
echo "$ ${CMD[*]}"
"${CMD[@]}"
STATUS=$?
echo
echo "exit code: $STATUS"

JSON_CMD=("${CMD[@]}" -f json -o "$REPORT_PATH")
"${JSON_CMD[@]}" >/dev/null
JSON_STATUS=$?
if [[ "$JSON_STATUS" -ne 0 && "$JSON_STATUS" -ne 1 ]] || [[ ! -s "$REPORT_PATH" ]]; then
  echo "failed to write JSON report: exit code $JSON_STATUS" >&2
  exit "$JSON_STATUS"
fi

echo "JSON report: $REPORT_PATH"
exit 0
