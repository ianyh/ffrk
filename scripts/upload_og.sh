#!/usr/bin/env bash
# Sync rendered OG cards (data/og/) to the R2 bucket the Worker serves from.
# Uses the S3-compatible R2 API via aws-cli; only changed files are uploaded.
#
# One-time setup (Cloudflare dashboard → R2 → Manage R2 API Tokens → create a
# token with Object Read & Write), then export:
#   export R2_ACCOUNT_ID=<your cloudflare account id>
#   export AWS_ACCESS_KEY_ID=<r2 token access key id>
#   export AWS_SECRET_ACCESS_KEY=<r2 token secret>
#   export R2_BUCKET=ffrk-og        # optional, this is the default
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${R2_ACCOUNT_ID:?set R2_ACCOUNT_ID (your Cloudflare account id)}"
: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID (R2 token)}"
: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY (R2 token)}"
: "${R2_BUCKET:=ffrk-og}"

# R2 expects region "auto" and the account-scoped endpoint.
export AWS_DEFAULT_REGION=auto
ENDPOINT="https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com"

echo "Syncing ${ROOT}/data/og/ → s3://${R2_BUCKET}/ (${ENDPOINT})"
aws s3 sync "${ROOT}/data/og/" "s3://${R2_BUCKET}/" \
  --endpoint-url "${ENDPOINT}" \
  --content-type image/png \
  --no-progress

echo "✓ done"
