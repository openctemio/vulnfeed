#!/usr/bin/env bash
# Tests .github/scripts/publish-release.sh against a fake gh that keeps one
# release in a directory. Run: bash .github/scripts/publish-release.test.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'find "$tmp" -delete' EXIT
mkdir -p "$tmp/bin" "$tmp/state" "$tmp/out"
export STATE="$tmp/state" GITHUB_REPOSITORY=o/r NOTES=/dev/null RETRY_PAUSE=0 BATCH_PAUSE=0
export PATH="$tmp/bin:$PATH"

# state/exists, state/draft, state/assets/<name>, state/uploads (log)
cat > "$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
set -e
a=$STATE/assets; mkdir -p "$a"
case "$1 $2" in
"release view")
  [ -e "$STATE/exists" ] || exit 1
  if [[ "$*" == *isDraft* ]]; then [ -e "$STATE/draft" ] && echo true || echo false; exit 0; fi
  if [[ "$*" == *assets* ]]; then for f in "$a"/*; do [ -e "$f" ] && printf '%s\t%s\n' "$(basename "$f")" "$(stat -c %s "$f")"; done; exit 0; fi ;;
"release create") touch "$STATE/exists" "$STATE/draft" ;;
"release upload")
  shift 3; while [ "$1" != --repo ]; do shift; done; shift 2
  [ "$1" = --clobber ] && shift
  [ -n "${FAIL_ONCE:-}" ] && [ ! -e "$STATE/failed" ] && { touch "$STATE/failed"; exit 1; }
  for f in "$@"; do cp "$f" "$a/$(basename "$f")"; echo "$(basename "$f")" >> "$STATE/uploads"; done ;;
"release delete-asset") find "$a/$4" -delete; echo "$4" >> "$STATE/deleted" ;;
"release edit") find "$STATE/draft" -delete ;;
esac
GH
chmod +x "$tmp/bin/gh"
script="$root/.github/scripts/publish-release.sh"
fail() { echo "FAIL: $*"; exit 1; }
reset() { find "$STATE" -mindepth 1 -delete; }

for i in 1 2 3; do printf 'chunk%s' "$i" > "$tmp/out/sha256-$i.jsonl.gz"; done
printf 'p1' > "$tmp/out/latest.dsse.json"

# 1. fresh release: everything uploaded, published
reset
bash "$script" v1-1 "$tmp/out" >/dev/null
[ ! -e "$STATE/draft" ] || fail "not published"
[ "$(wc -l < "$STATE/uploads")" = 4 ] || fail "want 4 uploads"

# 2. resume a draft holding some of the files plus a stale asset: identical
#    chunks are skipped, the stale one is deleted, the pointer is replaced
reset
touch "$STATE/exists" "$STATE/draft"; mkdir -p "$STATE/assets"
cp "$tmp/out/sha256-1.jsonl.gz" "$tmp/out/sha256-2.jsonl.gz" "$STATE/assets/"
printf 'old' > "$STATE/assets/sha256-stale.jsonl.gz"
printf 'old' > "$STATE/assets/latest.dsse.json"
FAIL_ONCE=1 bash "$script" v1-1 "$tmp/out" >/dev/null
grep -qx sha256-stale.jsonl.gz "$STATE/deleted" || fail "stale asset kept"
! grep -q 'sha256-[12]' "$STATE/uploads" || fail "identical chunk uploaded again"
grep -qx sha256-3.jsonl.gz "$STATE/uploads" || fail "missing chunk not uploaded"
[ "$(cat "$STATE/assets/latest.dsse.json")" = p1 ] || fail "pointer not replaced"
[ ! -e "$STATE/draft" ] || fail "not published"

# 3. a chunk with the same name but another size is uploaded again
reset
touch "$STATE/exists" "$STATE/draft"; mkdir -p "$STATE/assets"
printf 'cut' > "$STATE/assets/sha256-1.jsonl.gz"
bash "$script" v1-1 "$tmp/out" >/dev/null
grep -qx sha256-1.jsonl.gz "$STATE/uploads" || fail "wrong-size chunk kept"

# 4. already published with every file: nothing happens
reset
bash "$script" v1-1 "$tmp/out" >/dev/null
find "$STATE/uploads" -delete
bash "$script" v1-1 "$tmp/out" | grep -q 'already published' || fail "published release not recognised"
[ ! -e "$STATE/uploads" ] || fail "uploaded to a published release"

# 5. too many files are refused before anything is created
reset
MAX_ASSETS=2 bash "$script" v1-1 "$tmp/out" 2>/dev/null && fail "cap not enforced"
[ ! -e "$STATE/exists" ] || fail "release created despite the cap"
echo ok
