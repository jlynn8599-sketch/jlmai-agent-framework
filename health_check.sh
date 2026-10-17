#!/usr/bin/env bash
# JLMAI Health Check
# Copyright (c) 2026 JLM AI Agent LLC. All rights reserved.
# Author: Jessica Lynn Moss <jlmaiagent@astermail.org>
#
# Pulls the latest main, then queries the local dispatcher /health
# endpoint and pretty-prints the JSON result.
# Requires: the dispatcher running on http://127.0.0.1:8000, and jq.
set -euo pipefail

git pull origin main
curl -s http://127.0.0.1:8000/health | jq .
