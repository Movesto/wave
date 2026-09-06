#!/usr/bin/env bash
# Clone the npm repos behind the OSV TypeScript guard set.
#
# --filter=blob:none keeps history (so `git show {sha}^:path` works) while
# skipping file contents until asked for. --depth 1 would NOT work here: we need
# the parent commit of each fix.
#
# Resumable: existing directories are skipped, so a dropped connection just
# means re-running this. Repos deleted or renamed on GitHub fail and are logged;
# ~10% failure is normal and not a bug.
set -u
ROOT="tools/codeql_work/repos"
LIST="data/osv/js_repos_to_clone.txt"
FAIL="data/osv/js_clone_failures.txt"
mkdir -p "$ROOT"
: > "$FAIL"

total=$(grep -c . "$LIST")
i=0
# tr -d '\r': python-written lists carry CRLF on Windows and bash keeps the \r,
# which makes git create a directory with a stray character and then fail.
while IFS= read -r line; do
  line=$(printf '%s' "$line" | tr -d '\r')
  [ -z "$line" ] && continue
  i=$((i+1))
  owner="${line%%/*}"
  repo="${line##*/}"
  dir="$ROOT/${owner}__${repo}"
  if [ -d "$dir" ]; then
    echo "[$i/$total] skip (exists) $line"
    continue
  fi
  echo "[$i/$total] cloning $line"
  if ! git clone --filter=blob:none --quiet "https://github.com/${line}.git" "$dir" 2>/dev/null; then
    echo "$line" >> "$FAIL"
    rm -rf "$dir"
    echo "[$i/$total] FAILED $line"
  fi
done < "$LIST"

echo "done. failures: $(grep -c . "$FAIL" 2>/dev/null || echo 0)"
