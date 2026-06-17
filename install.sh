#!/bin/sh
# AgentHound collector installer.
#
# Pin to a release tag for integrity:
#   curl -sSfL https://raw.githubusercontent.com/adithyan-ak/agenthound/v<VERSION>/install.sh | sh
#
# Verifies the downloaded archive against checksums.txt before extracting,
# and against cosign signatures if cosign is available on $PATH.

set -e

GITHUB_REPO="adithyan-ak/agenthound"
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
  VERSION=$(curl -sSfL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
  if [ -z "$VERSION" ]; then
    echo "Error: could not determine latest release"; exit 1
  fi
else
  VERSION="$AGENTHOUND_VERSION"
fi

echo "Version:  ${VERSION}"
echo "Platform: ${OS}/${ARCH}"
echo ""

ARCHIVE="agenthound_${VERSION#v}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
TMPDIR=$(mktemp -d)
STAGE=$(mktemp -d)
trap 'rm -rf "$TMPDIR" "$STAGE"' EXIT

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
# cosign v3 bundles the signature + Fulcio certificate into one
# checksums.txt.sigstore.json (the old separate .sig/.pem are gone).
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

# Extract atomically: extract to staging dir, then mv
echo "Installing to ${INSTALL_DIR}/agenthound..."
mkdir -p "$INSTALL_DIR"
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$STAGE"
chmod 0755 "${STAGE}/agenthound"
mv "${STAGE}/agenthound" "${INSTALL_DIR}/agenthound"

# Verify the installed binary runs
if "${INSTALL_DIR}/agenthound" --version >/dev/null 2>&1; then
  echo ""
  echo "  Installed: ${INSTALL_DIR}/agenthound"
  "${INSTALL_DIR}/agenthound" --version | sed 's/^/  /'
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
  echo "    agenthound scan --output scan.json           # explicit path"
  echo "    agenthound scan --output - | ssh op-box agenthound-server ingest -"
  echo ""
else
  echo "Error: installed binary failed to run"
  exit 1
fi
