"""
crawl_github.py  (FIXED)
------------------------
Fetches GitHub Security Advisories via REST API.
Output: raw_github.json

FIXES:
  - Previously parse_advisory stored only cve_id and dropped entries where
    cve_id was null. 2,951 out of 3,000 advisories have only a GHSA ID.
  - Now stores ghsa_id always, cve_id when present, and also stores
    `all_cve_ids` — the full list of CVE aliases from the advisory.
    GitHub advisories can map to multiple CVEs via the identifiers field.
  - No longer filters out GHSA-only entries — they get stored with cve_id=""
    and are handled by build_dataset.py's Pass 3.
"""

import requests
import json
import os
import time
from tqdm import tqdm

GITHUB_API = "https://api.github.com/advisories"


def get_headers():
    token = os.getenv("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_page(page=1, per_page=100):
    params = {
        "per_page": per_page,
        "page":     page,
        "type":     "reviewed"
    }
    resp = requests.get(GITHUB_API, headers=get_headers(), params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def parse_advisory(adv: dict) -> dict:
    # ── Extract ALL CVE IDs from multiple fields ───────────────────────────
    # Field 1: top-level cve_id (single CVE GitHub has confirmed)
    primary_cve = adv.get("cve_id") or ""

    # Field 2: identifiers array — contains both GHSA and CVE type entries
    # e.g. [{"type": "GHSA", "value": "GHSA-xxx"}, {"type": "CVE", "value": "CVE-2021-44228"}]
    all_cve_ids = []
    for ident in adv.get("identifiers", []):
        if ident.get("type") == "CVE":
            all_cve_ids.append(ident["value"])
    # Also include the top-level cve_id if not already in the list
    if primary_cve and primary_cve not in all_cve_ids:
        all_cve_ids.insert(0, primary_cve)

    # Deduplicate while preserving order
    seen_cves = set()
    unique_cve_ids = []
    for c in all_cve_ids:
        if c and c not in seen_cves:
            seen_cves.add(c)
            unique_cve_ids.append(c)

    # ── Affected package info ──────────────────────────────────────────────
    affected     = adv.get("vulnerabilities", [])
    packages     = []
    fix_versions = []
    languages    = []

    for v in affected:
        pkg = v.get("package", {})
        if pkg.get("name"):
            packages.append(pkg["name"])
        if pkg.get("ecosystem"):
            languages.append(pkg["ecosystem"])
        pv = v.get("patched_versions", "")
        if pv:
            fix_versions.append(pv)

    # ── Build fix recommendation ───────────────────────────────────────────
    fix = ""
    if fix_versions:
        fix = f"Update to patched version(s): {', '.join(fix_versions)}"
    elif adv.get("summary"):
        fix = f"Refer to advisory: {adv['summary']}"

    return {
        "source":             "github_advisory",
        "ghsa_id":            adv.get("ghsa_id", ""),       # always present
        "cve_id":             primary_cve,                  # may be empty string
        "all_cve_ids":        unique_cve_ids,               # FIX: full alias list
        "vulnerability_name": adv.get("summary", ""),
        "description":        adv.get("description", ""),
        "cvss_score":         (adv.get("cvss") or {}).get("score", ""),
        "cvss_severity":      adv.get("severity", "").capitalize(),
        "cwe_ids":            [c["cwe_id"] for c in adv.get("cwes", [])],
        "affected_packages":  packages,
        "languages":          list(set(languages)),
        "fix_recommendation": fix,
        "published":          adv.get("published_at", ""),
        "references":         adv.get("references", [])[:5]
    }


def run(max_pages=30, out="data/raw_github.json"):
    all_advisories = []

    for page in tqdm(range(1, max_pages + 1), desc="GitHub advisories"):
        try:
            items = fetch_page(page)
            if not items:
                break
            for item in items:
                all_advisories.append(parse_advisory(item))
            time.sleep(0.5)
        except requests.exceptions.HTTPError as e:
            if "rate limit" in str(e).lower():
                print("  ⚠️  Rate limited. Set GITHUB_TOKEN env var for higher limits.")
                break
            print(f"  ⚠️  Page {page} failed: {e}")

    # Stats
    with_cve     = sum(1 for a in all_advisories if a["cve_id"])
    with_any_cve = sum(1 for a in all_advisories if a["all_cve_ids"])
    ghsa_only    = sum(1 for a in all_advisories if not a["cve_id"])

    print(f"\n  Total advisories:       {len(all_advisories)}")
    print(f"  With primary CVE ID:    {with_cve}")
    print(f"  With any CVE alias:     {with_any_cve}")
    print(f"  GHSA-only (no CVE):     {ghsa_only}")

    with open(out, "w") as f:
        json.dump(all_advisories, f, indent=2)

    print(f"\n✅ Saved {len(all_advisories)} GitHub advisories → {out}")


if __name__ == "__main__":
    run()