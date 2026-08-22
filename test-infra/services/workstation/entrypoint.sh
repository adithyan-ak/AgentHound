#!/bin/sh
set -eu

readonly FIXTURE_HOME=/opt/agenthound-workstation/home

restore_fixtures() {
    cp -a "${FIXTURE_HOME}/." "${HOME}/"
}

if [ "${1:-}" = "restore-fixtures" ]; then
    restore_fixtures
    exit 0
fi

restore_fixtures
if [ "$#" -eq 0 ]; then
    set -- sleep infinity
fi
exec "$@"
