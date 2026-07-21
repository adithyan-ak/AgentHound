#!/bin/sh
# Print the changelog title and newest version section for GoReleaser.
# This keeps public release notes curated while CHANGELOG.md remains the SSOT.

set -eu

changelog=${1:-CHANGELOG.md}

if [ ! -f "$changelog" ]; then
  echo "release-notes: changelog not found: $changelog" >&2
  exit 1
fi

awk '
  NR == 1 && /^# / {
    title = $0
    next
  }

  /^## v[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$)/ {
    sections++
    if (sections > 1) {
      exit
    }

    if (title != "") {
      print title
      print ""
    }
    emit = 1
  }

  emit {
    print
  }

  END {
    if (sections == 0) {
      print "release-notes: no version section found" > "/dev/stderr"
      exit 1
    }
  }
' "$changelog"
