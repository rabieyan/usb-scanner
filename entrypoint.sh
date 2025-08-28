#!/usr/bin/env bash
set -Eeuo pipefail

# Ensure output dir exists (mounted from host)
mkdir -p /out

# Optional: update virus db when container starts (comment out if offline)
# freshclam || true

python /app/scanner.py \
  --path /scan \
  --out-json /out/report.json \
  --out-csv /out/report.csv \
  ${YARA_RULES:+--yara-rules "$YARA_RULES"} \
  ${CLAMAV:+--clamav}
