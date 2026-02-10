#!/usr/bin/env bash

set -euo pipefail

SHOW_ZERO_ONLY=false
FAIL_ON_ZERO=false

# Function to display help
print_help() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --zero           Show only functions with 0.0% coverage
  --fail-on-zero   Fail (exit non-zero) if any function has 0.0% coverage
  --help           Show this help message and exit

Examples:
  $0                     # Run tests and show full coverage
  $0 --zero              # Show only functions with 0% coverage
  $0 --fail-on-zero      # Fail if any function has 0% coverage (CI-friendly)
  $0 --zero --fail-on-zero # Show 0% functions and fail if any exist
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

EXCLUDE_REGEX='/cmd/|/internal/api/types|/internal/api/server|internal/domain|internal/slurmclient'
PKGS=$(go list ./... | grep -vE "$EXCLUDE_REGEX")

# Silence go test output when we only care about zero coverage
if [[ "$SHOW_ZERO_ONLY" == true || "$FAIL_ON_ZERO" == true ]]; then
  go test $PKGS -cover -coverprofile=coverage.out > /dev/null
else
  go test $PKGS -cover -coverprofile=coverage.out
fi

if [[ "$FAIL_ON_ZERO" == true ]]; then
  # Print zero-coverage functions and fail if any exist
  go tool cover -func=coverage.out \
    | awk '$NF=="0.0%" { found=1; print } END { exit found }'
elif [[ "$SHOW_ZERO_ONLY" == true ]]; then
  # Just print zero-coverage functions
  go tool cover -func=coverage.out | awk '$NF=="0.0%"'
else
  # Full coverage output
  go tool cover -func=coverage.out
fi
