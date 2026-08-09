#!/usr/bin/env bash
# Phase-0/1 dataflow via Semgrep taint (Docker). Usage: ./run_semgrep.sh <dir> [rule.yaml]
DIR="${1:-phase0_cpg}"; RULE="${2:-phase0_cpg/taint_rule.yaml}"
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)/$DIR:/src" -v "$(pwd)/$(dirname "$RULE"):/rules" \
  semgrep/semgrep:latest semgrep --config="/rules/$(basename "$RULE")" --json --dataflow-traces /src
