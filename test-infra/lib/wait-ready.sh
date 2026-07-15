#!/usr/bin/env bash

wait_ready() {
  local compose_file="$1"
  local timeout_seconds="${2:-600}"
  local deadline=$((SECONDS + timeout_seconds))
  local services service container_id status
  local pending
  local -a compose=(docker compose -f "${compose_file}")

  services="$("${compose[@]}" config --services)"
  while ((SECONDS < deadline)); do
    pending=0
    for service in ${services}; do
      container_id="$("${compose[@]}" ps -q "${service}")"
      if [[ -z "${container_id}" ]]; then
        pending=1
        continue
      fi

      status="$(docker inspect --format \
        '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
        "${container_id}")"
      case "${status}" in
        healthy | running)
          ;;
        unhealthy | exited | dead)
          printf 'service %s entered terminal state %s\n' "${service}" "${status}" >&2
          "${compose[@]}" ps >&2
          return 1
          ;;
        *)
          pending=1
          ;;
      esac
    done

    if ((pending == 0)); then
      printf 'All compose services are ready.\n'
      return 0
    fi
    sleep 3
  done

  printf 'Timed out after %ss waiting for compose services.\n' "${timeout_seconds}" >&2
  "${compose[@]}" ps >&2
  return 1
}
