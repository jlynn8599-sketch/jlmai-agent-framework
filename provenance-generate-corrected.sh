#!/usr/bin/env bash
# ==============================================================================
# JLMAI Agent Framework v2.0.0 — HONEST local provenance generation.
# CORRECTED version. Fixes vs. the pasted draft:
#  1. NO FAKE GPG SIGNATURE. The draft wrote "signature_type: GPG",
#     "signed_by", and a "key_id" into provenance without ever running
#     any GPG signing command. A signature claim with no signature is
#     fabrication. This version honestly reports "signature": "none".
#  2. NO RE-CREATION of existing tag/release. v2.0.0 already exists on
#     GitHub. The draft's `git tag -s` and `gh release create` would both
#     FAIL ("already exists"). This script refuses to run if either
#     exists and tells you to use a new version instead.
#  3. NO MISSING-DIRECTORY FAILURE. The draft archived jlmai/ core/
#     config/ pyproject.toml README.md LICENSE — several of which do not
#     exist in the repo, so tar would fail under `set -e`. This version
#     archives the repo checkout (same exclusions as CI).
#  4. NO FALSE CLAIMS. Removed: LLC presented as existing (not filed
#     yet), AppArmor "enforced", UFW "loopback_isolated", systemd
#     watchdogs, Podman/bwrap, Rust build, unverified test coverage,
#     "verified" forensic audit, attached audit PDF, and the
#     "mainnet" vault target (contradicts Base Sepolia).
#  5. NO "merkle_root_hash" MISLABEL. The value was just the tarball
#     SHA-256, not a Merkle root. It is now honestly named
#     "tarball_sha256".
#  6. TARBALL WRITTEN TO /tmp FIRST. Same fix as the CI workflow:
#     tar must not write its output into the directory it archives.
#
# This script generates LOCAL provenance only. It does NOT publish
# a release and does NOT sign anything.
# ==============================================================================

set -euo pipefail

VERSION="v2.0.0"
PROJECT_NAME="jlmai-agent-framework"
ARCHIVE_NAME="${PROJECT_NAME}-${VERSION}-local.tar.gz"
PROVENANCE_FILE="provenance-local.json"

echo "[*] Local provenance generation for ${VERSION} (no signing, no publish)..."

# 1. Refuse to re-create an existing tag or release.
if git rev-parse "${VERSION}" >/dev/null 2>&1; then
  echo "[!] Tag ${VERSION} already exists locally. Use a new version." >&2
  exit 1
fi
if gh release view "${VERSION}" >/dev/null 2>&1; then
  echo "[!] Release ${VERSION} already exists on GitHub. This script does not overwrite it." >&2
  exit 1
fi

# 2. Clean previous LOCAL build artifacts only (never the published ones).
rm -f "${ARCHIVE_NAME}" "${PROVENANCE_FILE}"

# 3. Create distribution archive from the repo checkout, secrets excluded.
echo "[*] Packaging local archive..."
tar --exclude='.git' --exclude='.env' --exclude='.env.*' \
    --exclude='keys' --exclude='*.pem' --exclude='*.key' \
    --exclude='dist' --exclude='venv' --exclude='__pycache__' \
    --exclude='node_modules' --exclude='jlmai-framework-*.tar.gz' \
    -czf "/tmp/${ARCHIVE_NAME}" .
mv "/tmp/${ARCHIVE_NAME}" .

# 4. Generate SHA-256 Checksum.
SHA256_HASH=$(sha256sum "${ARCHIVE_NAME}" | awk '{print $1}')
echo "[+] Computed SHA-256 Checksum: ${SHA256_HASH}"

# 5. Generate HONEST provenance JSON manifest (no signature claims).
echo "[*] Generating ${PROVENANCE_FILE} manifest..."
cat << EOF > "${PROVENANCE_FILE}"
{
  "schema_version": "2.0.0",
  "project": "${PROJECT_NAME}",
  "author": "Jessica Lynn Moss",
  "organization": "JLM AI Agent LLC (NOT YET FORMED - SC Articles not filed as of 2026-10-17)",
  "contact": "jlmaiagent@astermail.org",
  "repository": "https://github.com/jlynn8599-sketch/${PROJECT_NAME}",
  "release_tag": "${VERSION}",
  "release_date": "$(date -u +%Y-%m-%d)",
  "release_scope": "Setup files only. The framework application code is NOT in the v2.0.0 GitHub release.",
  "tarball_sha256": "${SHA256_HASH}",
  "artifacts": [
    {
      "filename": "${ARCHIVE_NAME}",
      "sha256": "${SHA256_HASH}",
      "signature_type": "none",
      "signed_by": null,
      "key_id": null
    }
  ],
  "security_metadata": {
    "apparmor_profile": "unverified",
    "ufw_rules": "unverified",
    "systemd_watchdogs": "unverified",
    "blockchain_target": "Base Sepolia",
    "chain_id": 84532
  },
  "build_environment": {
    "os": "Linux x86_64",
    "runtime": ["Python (gateway)"],
    "containerization": "none - local build",
    "test_coverage": "unverified"
  },
  "forensic_audit": {
    "status": "none_performed",
    "audit_pdf_attached": false,
    "vault_target": null
  }
}
EOF

echo "[+] Local provenance complete: ${PROVENANCE_FILE}"
echo "[*] This did NOT sign anything and did NOT publish a release."
