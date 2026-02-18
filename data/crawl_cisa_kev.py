"""
crawl_cisa_kev.py
-----------------
Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog.
This is a CURATED, HIGH-VALUE data source — every entry is manually verified
by CISA analysts as actively exploited in the wild.

Why this matters:
  - NVD has 200k+ CVEs, most never exploited in practice
  - CISA KEV has ~1100 CVEs that ARE actively exploited
  - It's the gold standard for "real-world threat" data
  - Contains ransomware campaign associations not in NVD/EPSS
  - FREE, no auth, updated daily

Output: raw_cisa_kev.json
Catalog URL: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import requests
import json
import time
from pathlib import Path
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> dict:
    """Fetch and return the full KEV JSON catalog."""
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_kev_record(vuln: dict) -> dict:
    """
    Parse a single KEV entry into a dataset-ready record.
    Fields unique to KEV vs NVD:
      - requiredAction:         What defenders MUST do (CISA mandate)
      - dueDate:                Federal patch deadline
      - knownRansomwareCampaignUse: Whether ransomware groups exploit this
      - notes:                  CISA analyst notes, often with context not in NVD
    """
    cve_id = vuln.get("cveID", "")

    # Build an enriched description combining NVD description with KEV context
    kev_description = " | ".join(filter(None, [
        vuln.get("shortDescription", ""),
        f"Required action: {vuln.get('requiredAction', '')}" if vuln.get("requiredAction") else "",
        f"Known ransomware use: {vuln.get('knownRansomwareCampaignUse', '')}"
    ]))

    return {
        "source":                    "cisa_kev",
        "cve_id":                    cve_id,
        "vendor":                    vuln.get("vendorProject", ""),
        "product":                   vuln.get("product", ""),
        "vulnerability_name":        vuln.get("vulnerabilityName", ""),
        "description":               vuln.get("shortDescription", ""),
        "kev_description":           kev_description,
        "required_action":           vuln.get("requiredAction", ""),
        "due_date":                  vuln.get("dueDate", ""),
        "date_added":                vuln.get("dateAdded", ""),
        "known_ransomware":          vuln.get("knownRansomwareCampaignUse", "Unknown"),
        "notes":                     vuln.get("notes", ""),
        # Signals that this CVE is confirmed exploited — highest-priority training signal
        "confirmed_exploited":       True,
        "cves_mentioned":            [cve_id] if cve_id else []
    }


def run(out: str = "data/raw_cisa_kev.json"):
    print("Fetching CISA Known Exploited Vulnerabilities catalog...")
    try:
        raw = fetch_kev()
    except Exception as e:
        print(f"❌ Failed to fetch CISA KEV: {e}")
        return

    catalog_version = raw.get("catalogVersion", "unknown")
    date_released   = raw.get("dateReleased", "unknown")
    vulns           = raw.get("vulnerabilities", [])

    print(f"  Catalog version: {catalog_version}")
    print(f"  Date released:   {date_released}")
    print(f"  Total entries:   {len(vulns)}")

    records = [parse_kev_record(v) for v in vulns]

    # Stats
    ransomware_count = sum(1 for r in records if r["known_ransomware"] == "Known")
    vendors          = list(set(r["vendor"] for r in records if r["vendor"]))
    print(f"\n  Ransomware-associated CVEs: {ransomware_count}")
    print(f"  Unique vendors:             {len(vendors)}")
    print(f"  Top vendors: {', '.join(sorted(vendors)[:10])}")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved {len(records)} CISA KEV records → {out}")


if __name__ == "__main__":
    run()