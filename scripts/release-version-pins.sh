#!/usr/bin/env bash
# Shared manifest and patterns for public release-version references.

# Keep this list limited to live installation surfaces. Historical changelog
# examples, dependency versions, and test fixture versions are intentionally
# excluded.
release_version_pin_specs() {
  cat <<'EOF'
installer|install.sh|1
environment|install.sh|1
readme-label|README.md|1
installer|README.md|1
environment|README.md|1
compose|README.md|1
installer|docs/getting-started/install.md|1
environment|docs/getting-started/install.md|1
compose|docs/getting-started/install.md|1
compose|docs/getting-started/quickstart.md|1
compose|docs/operator/deployment.md|2
EOF
}

release_version_pin_pattern() {
  local kind=$1
  local semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
  case "$kind" in
    installer)
      printf '%s' "https://raw\.githubusercontent\.com/adithyan-ak/agenthound/(v)?${semver}/install\.sh"
      ;;
    environment)
      printf '%s' "AGENTHOUND_VERSION=${semver}"
      ;;
    compose)
      printf '%s' "https://raw\.githubusercontent\.com/adithyan-ak/agenthound/(v)?${semver}/docker/docker-compose\.public\.yml"
      ;;
    readme-label)
      printf '%s' "Install the ${semver} static binary"
      ;;
    *)
      echo "unknown release-version pin kind: $kind" >&2
      return 1
      ;;
  esac
}

release_version_pin_replacement() {
  local kind=$1 version=$2
  case "$kind" in
    installer)
      printf 'https://raw.githubusercontent.com/adithyan-ak/agenthound/%s/install.sh' "$version"
      ;;
    environment)
      printf 'AGENTHOUND_VERSION=%s' "$version"
      ;;
    compose)
      printf 'https://raw.githubusercontent.com/adithyan-ak/agenthound/%s/docker/docker-compose.public.yml' "$version"
      ;;
    readme-label)
      printf 'Install the %s static binary' "$version"
      ;;
    *)
      echo "unknown release-version pin kind: $kind" >&2
      return 1
      ;;
  esac
}
