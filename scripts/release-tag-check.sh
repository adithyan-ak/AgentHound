#!/usr/bin/env bash
# Enforce the numeric release policy.

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

    is_numeric_semver "$latest" || {
      echo "release-tag-check: latest release is not strict numeric SemVer: $latest" >&2
      exit 1
    }
    semver_is_greater "$tag" "$latest" || {
      echo "release-tag-check: $tag must be newer than $latest" >&2
      exit 1
    }
    git merge-base --is-ancestor "$tag_commit" "${main_ref}^{commit}" || {
      echo "release-tag-check: release tag must already be contained in main" >&2
      exit 1
    }
    echo "$tag_commit"
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
    git rev-parse --verify "${main_ref}^{commit}" >/dev/null
    if ! git merge-base --is-ancestor "$tag_commit" "${main_ref}^{commit}"; then
      echo "release-tag-check: published release tag is not contained in main" >&2
      exit 1
    fi
    echo "$tag_commit"
    ;;
  *)
    usage
    ;;
esac
