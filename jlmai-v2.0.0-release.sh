#!/usr/bin/env bash
# JLMAI Framework v2.0.0 — GitHub release sequence
# Run in the repo directory on your machine.
#
# BEFORE RUNNING:
#   1. Tarball (jlmai-framework-v2.0.0-release.tar.gz) built with the
#      fixed packaging script (secrets excluded) and contents verified.
#   2. provenance.json holds REAL values (GPG key ID, SHA-256 hashes),
#      not placeholders.

# Ensure clean tag state
git tag -d v2.0.0 2>/dev/null || true

if git config --get user.signingkey >/dev/null 2>&1; then
  git tag -s v2.0.0 -m "JLMAI Framework v2.0.0"
else
  git tag -a v2.0.0 -m "JLMAI Framework v2.0.0"
fi

cat << 'EOF' > RELEASE_NOTES.md
# JLMAI Framework v2.0.0

Release v2.0.0 of the JLMAI Agent Framework introduces multi-agent coordination pipelines, high-throughput asynchronous task dispatching, EVM smart contract integration, and hardened system observability features.

## Highlights

* **Asynchronous Multi-Agent Dispatcher:** High-performance task distribution powered by Python (`asyncio`, FastAPI, aiokafka) and Rust (`Tokio`, PyO3).
* **Zero-Knowledge Proof Verification:** Groth16 circuit integration using Circom, snarkjs, and Arkworks modules.
* **Smart Contract Integration:** Contracts deployed on Base Sepolia testnet using Foundry (`JLMAI.sol` via `DeployJLMAI.s.sol`). Testnet deployment only -- not real-money settlement.
* **Security & Observability:** Hardened container profiles, Prometheus metrics endpoints, Grafana dashboard provisioning, and GPG-signed commits and tags.

## Artifacts

* `jlmai-framework-v2.0.0-release.tar.gz`
* `provenance.json`
EOF

if ! git config --get user.signingkey >/dev/null 2>&1; then
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' 's/, and GPG-signed commits and tags/./' RELEASE_NOTES.md
  else
    sed -i 's/, and GPG-signed commits and tags/./' RELEASE_NOTES.md
  fi
fi

git push origin v2.0.0 --force
gh release create v2.0.0 --title "JLMAI Framework v2.0.0" --notes-file RELEASE_NOTES.md jlmai-framework-v2.0.0-release.tar.gz provenance.json
