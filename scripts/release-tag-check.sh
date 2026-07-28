#!/usr/bin/env bash
# Enforce the one-time no-v migration and the normal numeric release policy.

set -euo pipefail

usage() {
  echo "usage: $0 candidate TAG LATEST_RELEASE MAIN_REF" >&2
  echo "       $0 published TAG MAIN_REF" >&2
  exit 2
}

is_numeric_semver() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

semver_is_greater() {
  local candidate=$1 current=$2
  local candidate_major candidate_minor candidate_patch
  local current_major current_minor current_patch
  IFS=. read -r candidate_major candidate_minor candidate_patch <<<"$candidate"
  IFS=. read -r current_major current_minor current_patch <<<"$current"

  (( candidate_major > current_major )) ||
    (( candidate_major == current_major && candidate_minor > current_minor )) ||
    (( candidate_major == current_major && candidate_minor == current_minor && candidate_patch > current_patch ))
}

mode=${1:-}
case "$mode" in
  candidate)
    [ "$#" -eq 4 ] || usage
    tag=$2
    latest=$3
    main_ref=$4
    is_numeric_semver "$tag" || {
      echo "release-tag-check: tag must be strict numeric SemVer: $tag" >&2
      exit 1
    }
    git rev-parse --verify "${tag}^{commit}" >/dev/null
    git rev-parse --verify "${main_ref}^{commit}" >/dev/null
    tag_commit=$(git rev-parse "${tag}^{commit}")
    main_commit=$(git rev-parse "${main_ref}^{commit}")

    if [ "$tag" = "1.0.0" ] && [ "$latest" = "v1.0.1" ]; then
      parent_line=$(git rev-list --parents -n 1 "$tag_commit")
      # A non-merge commit produces exactly two words: commit and one parent.
      if [ "$(printf '%s\n' "$parent_line" | awk '{print NF}')" -ne 2 ]; then
        echo "release-tag-check: migration candidate must have exactly one parent" >&2
        exit 1
      fi
      parent_commit=$(printf '%s\n' "$parent_line" | awk '{print $2}')
      if [ "$parent_commit" != "$main_commit" ]; then
        echo "release-tag-check: migration parent $parent_commit is not current main $main_commit" >&2
        exit 1
      fi
      echo migration
      exit 0
    fi

    is_numeric_semver "$latest" || {
      echo "release-tag-check: latest release $latest is not numeric; migration exception is unavailable" >&2
      exit 1
    }
    semver_is_greater "$tag" "$latest" || {
      echo "release-tag-check: $tag must be newer than $latest" >&2
      exit 1
    }
    git merge-base --is-ancestor "$tag_commit" "$main_commit" || {
      echo "release-tag-check: normal release tag must already be contained in main" >&2
      exit 1
    }
    echo normal
    ;;
  published)
    [ "$#" -eq 3 ] || usage
    tag=$2
    main_ref=$3
    is_numeric_semver "$tag" || {
      echo "release-tag-check: tag must be strict numeric SemVer: $tag" >&2
      exit 1
    }
    tag_commit=$(git rev-parse --verify "${tag}^{commit}")
    main_commit=$(git rev-parse --verify "${main_ref}^{commit}")
    if [ "$tag_commit" != "$main_commit" ]; then
      echo "release-tag-check: main $main_commit does not equal peeled tag commit $tag_commit" >&2
      exit 1
    fi
    echo "$tag_commit"
    ;;
  *)
    usage
    ;;
esac
