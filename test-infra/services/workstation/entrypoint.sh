#!/bin/sh
set -eu

readonly FIXTURE_HOME=/opt/agenthound-workstation/home

restore_fixtures() {
    cp -a "${FIXTURE_HOME}/." "${HOME}/"
    mkdir -p "${HOME}/.agenthound"
    touch \
        "${HOME}/.agenthound/loot-acknowledged" \
        "${HOME}/.agenthound/poison-acknowledged" \
        "${HOME}/.agenthound/extract-acknowledged" \
        "${HOME}/.agenthound/campaign-acknowledged"
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
