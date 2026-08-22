#!/bin/sh
# AgentHound collector installer.
#
# Pin to a release tag for integrity:
#   curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/1.1.1/install.sh \
#     | AGENTHOUND_VERSION=1.1.1 sh
#
# Verifies the downloaded archive against checksums.txt before extracting,
# and against cosign signatures if cosign is available on $PATH.

set -e

# Canonical owner/repo case matters: GitHub URLs are case-insensitive, but the
# cosign keyless signature's certificate identity (SAN) is the exact slug the
# release workflow ran under, so this must match it verbatim or cosign rejects it.
GITHUB_REPO="adithyan-ak/AgentHound"
INSTALL_DIR="${AGENTHOUND_INSTALL_DIR:-$HOME/.local/bin}"

echo ""
echo "  AgentHound Collector Installer"
echo "  =============================="
echo ""

# Detect OS / arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Error: unsupported architecture: $ARCH"; exit 1 ;;
esac

# Resolve version. Default to the latest GitHub Release tag.
if [ -z "$AGENTHOUND_VERSION" ]; then
  # Resolve "latest" via the github.com redirect, NOT api.github.com. The REST
  # API is rate-limited to 60 requests/hour per IP for anonymous callers, which
  # is permanently exhausted behind shared / corporate NAT egress IPs and breaks
  # the installer with a 403. The /releases/latest redirect carries no such
  # budget: it 302s to /releases/tag/<version>, which we parse out.
  resolved=$(curl -sSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${GITHUB_REPO}/releases/latest" || true)
  VERSION=${resolved##*/tag/}
  if [ -z "$VERSION" ] || [ "$VERSION" = "$resolved" ]; then
    echo "Error: could not determine latest release"
    echo "       Set AGENTHOUND_VERSION=X.Y.Z to pin a specific version."
    exit 1
  fi
else
  VERSION="$AGENTHOUND_VERSION"
fi

echo "Version:  ${VERSION}"
echo "Platform: ${OS}/${ARCH}"
echo ""

ARCHIVE="agenthound_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
TMPDIR=$(mktemp -d)
STAGE=$(mktemp -d)
INSTALL_TMP=""
INSTALL_BACKUP=""
INSTALL_PROMOTED=0

rollback_install() {
  if [ "$INSTALL_PROMOTED" -ne 1 ]; then
    return 0
  fi
  if [ -n "$INSTALL_BACKUP" ] && [ -e "$INSTALL_BACKUP" ]; then
    if ! mv "$INSTALL_BACKUP" "${INSTALL_DIR}/agenthound"; then
      return 1
    fi
    INSTALL_BACKUP=""
  else
    if ! rm -f "${INSTALL_DIR}/agenthound"; then
      return 1
    fi
  fi
  INSTALL_PROMOTED=0
}

cleanup() {
  status=$?
  rollback_ok=1
  trap - EXIT
  if ! rollback_install; then
    echo "Error: failed to restore the previous AgentHound installation" >&2
    if [ -n "$INSTALL_BACKUP" ]; then
      echo "       Recovery copy preserved at: $INSTALL_BACKUP" >&2
    fi
    rollback_ok=0
    status=1
  fi
  rm -rf "$TMPDIR" "$STAGE"
  if [ -n "$INSTALL_TMP" ]; then
    rm -f "$INSTALL_TMP"
  fi
  if [ -n "$INSTALL_BACKUP" ] && [ "$rollback_ok" -eq 1 ]; then
    rm -f "$INSTALL_BACKUP"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

echo "Downloading ${ARCHIVE}..."
curl -sSfL -o "${TMPDIR}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl -sSfL -o "${TMPDIR}/checksums.txt" "${BASE_URL}/checksums.txt"

# Verify checksum (mandatory — fail closed)
echo "Verifying checksum..."
cd "$TMPDIR"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --ignore-missing -c checksums.txt
elif command -v shasum >/dev/null 2>&1; then
  grep -E "  ${ARCHIVE}\$" checksums.txt | shasum -a 256 -c
else
  echo "Error: neither sha256sum nor shasum found; cannot verify integrity"
  exit 1
fi

# Optional: cosign signature verification.
# cosign v3 bundles the signature and Fulcio certificate into one
# checksums.txt.sigstore.json file.
if command -v cosign >/dev/null 2>&1; then
  echo "Verifying cosign signature..."
  curl -sSfL -o "${TMPDIR}/checksums.txt.sigstore.json" "${BASE_URL}/checksums.txt.sigstore.json"
  cosign verify-blob \
    --bundle "${TMPDIR}/checksums.txt.sigstore.json" \
    --certificate-identity "https://github.com/${GITHUB_REPO}/.github/workflows/release.yml@refs/tags/${VERSION}" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "${TMPDIR}/checksums.txt"
else
  cat <<EOF >&2

NOTE: cosign not found on PATH; skipping signature verification.
To verify manually, install cosign and run:

  cosign verify-blob \\
    --bundle ${BASE_URL}/checksums.txt.sigstore.json \\
    --certificate-identity 'https://github.com/${GITHUB_REPO}/.github/workflows/release.yml@refs/tags/${VERSION}' \\
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
    checksums.txt

EOF
fi

# Validate in staging before touching the current installation, then promote a
# destination-local temporary file with rename(2). A private backup permits an
# exact rollback if execution fails only from the installed path.
echo "Installing to ${INSTALL_DIR}/agenthound..."
mkdir -p "$INSTALL_DIR"
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$STAGE"
chmod 0755 "${STAGE}/agenthound"
if ! "${STAGE}/agenthound" --version >/dev/null 2>&1; then
  echo "Error: downloaded binary failed to run"
  exit 1
fi

INSTALL_TMP=$(mktemp "${INSTALL_DIR}/.agenthound.install.XXXXXX")
cp "${STAGE}/agenthound" "$INSTALL_TMP"
chmod 0755 "$INSTALL_TMP"

if [ -e "${INSTALL_DIR}/agenthound" ]; then
  INSTALL_BACKUP=$(mktemp "${INSTALL_DIR}/.agenthound.backup.XXXXXX")
  cp -p "${INSTALL_DIR}/agenthound" "$INSTALL_BACKUP"
fi
# Do not let a signal land between the atomic rename and the state transition
# that tells the EXIT trap to restore the backup.
trap '' HUP INT TERM
if ! mv "$INSTALL_TMP" "${INSTALL_DIR}/agenthound"; then
  trap 'exit 130' HUP INT TERM
  exit 1
fi
INSTALL_TMP=""
INSTALL_PROMOTED=1
trap 'exit 130' HUP INT TERM

# Verify the installed binary runs
if installed_version=$("${INSTALL_DIR}/agenthound" --version 2>/dev/null); then
  INSTALL_PROMOTED=0
  if [ -n "$INSTALL_BACKUP" ]; then
    rm -f "$INSTALL_BACKUP"
    INSTALL_BACKUP=""
  fi
  echo ""
  echo "  Installed: ${INSTALL_DIR}/agenthound"
  printf '%s\n' "$installed_version" | sed 's/^/  /'
  echo ""
  case ":$PATH:" in
    *":${INSTALL_DIR}:"*) ;;
    *) echo "  Add ${INSTALL_DIR} to your PATH:"
       echo '    export PATH="$HOME/.local/bin:$PATH"'
       echo ""
       ;;
  esac
  echo "  Quick start:"
  echo "    agenthound scan                              # writes ./scan-<scan_id>.json in CWD"
  echo "    agenthound scan --deep --output scan.json    # deeper collection and active proof"
  echo "    agenthound-server ingest scan.json           # run later on the analysis host"
  echo ""
else
  echo "Error: installed binary failed to run"
  exit 1
fi
