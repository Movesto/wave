#!/usr/bin/env bash
# Clone the repos needed by data/crossfile_candidates.tsv (guard-prefiltered CVE
# fixes). Partial clones: --filter=blob:none keeps full history so `git show
# {sha}:path` works, while skipping blob download until something is read.
# --depth 1 would NOT work here — the builder needs the fix commit and its parent.
#
# Resumable: an existing directory is skipped, so re-running after a power cut
# picks up where it stopped.
set -u
LIST=/tmp/repos.txt
DEST=tools/codeql_work/repos
FAILED=data/crossfile_clone_failures.txt
tr -d '\r' < data/crossfile_repos_to_clone.txt > "$LIST"
total=$(wc -l < "$LIST")
: > "$FAILED"
n=0; ok=0; fail=0; skip=0
start=$(date +%s)
while read -r r; do
  [ -z "$r" ] && continue
  n=$((n+1))
  d="$DEST/${r//\//__}"
  if [ -d "$d" ]; then skip=$((skip+1)); continue; fi
  if timeout 180 git clone --quiet --filter=blob:none "https://github.com/$r.git" "$d" 2>/dev/null; then
    ok=$((ok+1))
  else
    fail=$((fail+1)); echo "$r" >> "$FAILED"; rm -rf "$d" 2>/dev/null
  fi
  if [ $((n % 25)) -eq 0 ]; then
    el=$(( $(date +%s) - start ))
    echo "[$n/$total] ok=$ok fail=$fail skip=$skip  ${el}s elapsed"
  fi
done < "$LIST"
echo "DONE: $ok cloned, $fail failed, $skip already present, $(( $(date +%s) - start ))s"
echo "disk: $(du -sh $DEST 2>/dev/null | cut -f1)"
