#!/bin/sh
# Print the changelog title and newest version section for GoReleaser.

set -eu

changelog=${1:-CHANGELOG.md}
expected=${2:-}
expected=${expected#v}

if [ ! -f "$changelog" ]; then
  echo "release-notes: changelog not found: $changelog" >&2
  exit 1
fi
if [ -n "$expected" ] && ! printf '%s\n' "$expected" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "release-notes: invalid expected version: $expected" >&2
  exit 1
fi

awk -v expected="$expected" '
  NR == 1 && /^# / {
    title = $0
    next
  }

  /^## v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)/ {
    sections++
    if (sections > 1) {
      exit
    }

    version = $0
    sub(/^## v/, "", version)
    sub(/[[:space:]].*$/, "", version)
    if (expected != "" && version != expected) {
      print "release-notes: newest version v" version " does not match expected v" expected > "/dev/stderr"
      exit 2
    }
    if (title != "") {
      print title
      print ""
    }
    emit = 1
  }

  emit {
    print
    if ($0 !~ /^## / && $0 ~ /[^[:space:]]/) {
      body = 1
    }
  }

  END {
    if (sections == 0) {
      print "release-notes: no version section found" > "/dev/stderr"
      exit 1
    }
    if (!body) {
      print "release-notes: newest version section is empty" > "/dev/stderr"
      exit 1
    }
  }
' "$changelog"
