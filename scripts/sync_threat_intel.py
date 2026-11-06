#!/usr/bin/env python3
"""Refresh kev.json and epss.json from public sources.

  CISA KEV : https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  EPSS     : https://api.first.org/data/v1/epss

Usage:  python scripts/sync_threat_intel.py [output_dir]
Defaults to app/data (or $INTEL_DIR). Restart the API/worker afterwards - intel is loaded once at start.
EPSS is fetched for every KEV entry plus every CVE in the local catalog.
"""

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={ids}"
BATCH = 100


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "vulncorrelator-sync/1.0"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 - fixed https URLs
        return json.load(resp)


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else os.getenv("INTEL_DIR", "app/data"))
    kev = fetch_json(KEV_URL)
    kev_ids = sorted(v["cveID"].upper() for v in kev["vulnerabilities"])
    catalog_file = out / "cve_catalog.json"
    catalog_ids = (
        [e["cve_id"].upper() for e in json.loads(catalog_file.read_text()).get("entries", [])]
        if catalog_file.exists()
        else []
    )
    ids = sorted(set(kev_ids) | set(catalog_ids))

    scores: dict[str, float] = {}
    for i in range(0, len(ids), BATCH):
        batch = ids[i : i + BATCH]
        for row in fetch_json(EPSS_URL.format(ids=",".join(batch))).get("data", []):
            scores[row["cve"].upper()] = float(row["epss"])
        time.sleep(0.5)  # be polite to the API

    stamp = time.strftime("%Y-%m-%d")
    (out / "kev.json").write_text(
        json.dumps({"_meta": {"source": KEV_URL, "synced": stamp}, "cve_ids": kev_ids}, indent=1)
    )
    (out / "epss.json").write_text(
        json.dumps({"_meta": {"source": "api.first.org", "synced": stamp}, "scores": scores}, indent=1)
    )
    print(f"KEV: {len(kev_ids)} CVEs, EPSS: {len(scores)} scores -> {out}")


if __name__ == "__main__":
    main()
