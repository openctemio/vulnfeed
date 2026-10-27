#!/usr/bin/env bash
# Publishes the files of a bundle directory as the GitHub release TAG.
# Usage: publish-release.sh TAG DIR   (env: GITHUB_REPOSITORY, GH_TOKEN, NOTES, TITLE)
#
# Safe to run again after any failure:
#  - an existing DRAFT of the tag is resumed, not recreated;
#  - a content-addressed chunk (sha256-*) already there with the same size is
#    not uploaded again; every other file is replaced;
#  - a draft asset that is not part of this bundle is deleted (an older build
#    of the same tag would otherwise count against GitHub's 1000-asset cap);
#  - a tag that is already published with every file is left alone.
# The release stays a draft, which platforms (releases/latest) never see,
# until every file is there.
set -euo pipefail
tag=${1:?tag}
dir=${2:?dir}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY}
notes=${NOTES:-notes.md}
max_assets=${MAX_ASSETS:-900}

mapfile -t files < <(find "$dir" -maxdepth 1 -type f | sort)
want=${#files[@]}
if [ "$want" -gt "$max_assets" ]; then
  echo "bundle has $want files, more than $max_assets (GitHub allows 1000 per release)" >&2
  exit 1
fi

retry() { # retry CMD...: six attempts, growing pause
  local attempt
  for attempt in 1 2 3 4 5 6; do
    if "$@"; then return 0; fi
    [ "$attempt" = 6 ] && return 1
    sleep $((attempt * ${RETRY_PAUSE:-30}))
  done
}

assets() { gh release view "$tag" --repo "$repo" --json assets --jq '.assets[] | "\(.name)\t\(.size)"'; }

if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  draft=$(gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft)
else
  gh release create "$tag" --repo "$repo" --title "${TITLE:-$tag}" --notes-file "$notes" --draft
  draft=true
fi

declare -A remote=()
while IFS=$'\t' read -r name size; do
  [ -n "$name" ] && remote[$name]=$size
done < <(assets)

if [ "$draft" != true ]; then
  for f in "${files[@]}"; do
    [ -n "${remote[$(basename "$f")]+x}" ] || { echo "release $tag is published without $(basename "$f")" >&2; exit 1; }
  done
  echo "release $tag is already published with all $want files"
  exit 0
fi

declare -A local_names=()
todo=()
for f in "${files[@]}"; do
  name=$(basename "$f")
  local_names[$name]=1
  size=$(stat -c %s "$f")
  if [[ $name == sha256-* && ${remote[$name]:-} == "$size" ]]; then
    continue
  fi
  todo+=("$f")
done
for name in "${!remote[@]}"; do
  [ -n "${local_names[$name]+x}" ] || retry gh release delete-asset "$tag" "$name" --repo "$repo" --yes
done

echo "uploading ${#todo[@]} of $want files (the rest are already there)"
for ((i = 0; i < ${#todo[@]}; i += 20)); do
  retry gh release upload "$tag" --repo "$repo" --clobber "${todo[@]:i:20}"
  sleep "${BATCH_PAUSE:-3}"
done

have=$(assets | wc -l)
[ "$have" = "$want" ] || { echo "release $tag has $have of $want assets" >&2; exit 1; }
gh release edit "$tag" --repo "$repo" --draft=false --latest
