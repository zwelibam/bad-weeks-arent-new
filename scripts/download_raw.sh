#!/usr/bin/env bash
# Re-download the bulk datasets into raw/ (about 490 MB). Run from the repo root.
# Values in charts/data/*.csv were computed from the versions retrieved on 2026-10-25;
# re-downloading gives today's data, so the numbers will drift.
set -euo pipefail
mkdir -p raw
curl -fsSL -o raw/known_exploited_vulnerabilities.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
for y in $(seq 2002 "$(date +%Y)"); do
  curl -fsSL -o "raw/nvdcve-2.0-$y.json.gz" "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-$y.json.gz"
done
for e in npm PyPI; do
  curl -fsSL -o "raw/osv-$e-all.zip" "https://osv-vulnerabilities.storage.googleapis.com/$e/all.zip"
done
# aggregate.py expects this filename; it reads the current EPSS file saved under the 2026-10-24 name.
curl -fsSL -o raw/epss_scores-2026-10-24.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
echo "Done. Next: python3 scripts/aggregate.py && python3 charts/make_charts.py"
