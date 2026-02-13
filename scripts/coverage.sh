#!/usr/bin/env bash

set -euo pipefail

SHOW_ZERO_ONLY=false
FAIL_ON_ZERO=false
OPEN_HTML=false

# Function to display help
print_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --zero           Show only functions with 0.0% coverage
  --fail-on-zero   Fail (exit non-zero) if any function has 0.0% coverage
  --html           Generate coverage.html
  --help           Show this help message and exit
EOF
}

# Parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --zero)
      SHOW_ZERO_ONLY=true
      shift
      ;;
    --fail-on-zero)
      FAIL_ON_ZERO=true
      shift
      ;;
    --html)
      OPEN_HTML=true
      shift
      ;;
    --help)
      print_help
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      print_help
      exit 1
      ;;
  esac
done

mapfile -t PKGS < <(go list ./...)

# Run tests with coverage and preserve failure output for diagnosability.
if [[ "$SHOW_ZERO_ONLY" == true || "$FAIL_ON_ZERO" == true ]]; then
  TEST_LOG=$(mktemp)
  if ! go test "${PKGS[@]}" -cover -coverprofile=coverage.out >"$TEST_LOG" 2>&1; then
    cat "$TEST_LOG" >&2
    rm -f "$TEST_LOG"
    exit 1
  fi
  rm -f "$TEST_LOG"
else
  go test "${PKGS[@]}" -cover -coverprofile=coverage.out
fi

if [[ "$FAIL_ON_ZERO" == true ]]; then
  # Print zero-coverage functions and fail if any exist
  go tool cover -func=coverage.out \
    | awk '$NF=="0.0%" { found=1; print } END { exit found }'
elif [[ "$SHOW_ZERO_ONLY" == true ]]; then
  # Just print zero-coverage functions
  ZERO_OUTPUT=$(go tool cover -func=coverage.out | awk '$NF=="0.0%"')
  if [[ -n "$ZERO_OUTPUT" ]]; then
    printf '%s\n' "$ZERO_OUTPUT"
  else
    echo "No functions at 0.0% coverage"
  fi
else
  # Full coverage output
  go tool cover -func=coverage.out
fi

if [[ "$OPEN_HTML" == true ]]; then
  HTML_REPORT=coverage.html
  go tool cover -html=coverage.out -o "$HTML_REPORT"

  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$HTML_REPORT" >/dev/null 2>&1 || true
  elif command -v open >/dev/null 2>&1; then
    open "$HTML_REPORT" >/dev/null 2>&1 || true
  elif command -v start >/dev/null 2>&1; then
    start "$HTML_REPORT" >/dev/null 2>&1 || true
  fi

  echo "HTML report generated: $HTML_REPORT"
fi
