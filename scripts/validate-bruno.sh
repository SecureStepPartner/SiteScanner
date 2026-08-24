#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
collection_dir="$repo_root/bruno"
failed=0
count=0

while IFS= read -r file; do
  count=$((count + 1))
  grep -Eq '^  method: GET$' "$file" || { echo "error: non-GET request: ${file#"$repo_root/"}" >&2; failed=1; }
  grep -Fq 'forwardAuthorizationHeader: false' "$file" || { echo "error: auth forwarding not disabled: ${file#"$repo_root/"}" >&2; failed=1; }
done < <(find "$collection_dir" -type f -name '*.yml' ! -name 'opencollection.yml' ! -path '*/environments/*' | sort)

[[ $count -gt 0 ]] || { echo "error: no requests found" >&2; failed=1; }

if grep -RInE --exclude='*.example.yml' --exclude-dir=node_modules '(Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9_-]{20,}|(api[_-]?token|api[_-]?key|secret)[[:space:]]*[:=][[:space:]]*[A-Za-z0-9_-]{20,})' "$collection_dir"; then
  echo "error: possible credential in Bruno files" >&2
  failed=1
fi

[[ $failed -eq 0 ]] || exit 1
echo "SiteScanner Bruno safety checks passed ($count requests)."
