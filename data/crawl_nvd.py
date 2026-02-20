"""
crawl_nvd.py
------------
Fetches CVE records from NVD API v2.0.

FIX: Incremental fetch + cache staleness check.
  Previous behaviour: always fetched 10,000 CVEs from startIndex=0.
  This took ~45 min and ignored all previously fetched data.

  New behaviour:
    1. If raw_nvd.json is fresh (< 24h old) → skip fetch entirely.
    2. If raw_nvd.json exists but is stale → incremental mode:
         - Reads the most recent 'published' date from existing records
         - Fetches ONLY CVEs published since that date (± 7-day safety buffer)
         - Merges new records into existing file, deduplicating by cve_id
    3. If raw_nvd.json is missing → full fetch as before.

  Practical impact:
    Full pipeline re-run on --correlate or --from-build:
      Before: ~45 min NVD step regardless
      After:  < 30 sec (cache fresh) or ~3 min (incremental, ~200 new CVEs/day)

Output: data/raw_nvd.json
Schema: [{cve_id, vulnerability_name, cwe_id, description,
          cvss_score, cvss_severity, affected_software, published, references}]
"""

import requests
import json
import time
from pathlib import Path
from tqdm import tqdm

# Import cache utilities (see data/crawler_cache.py)
from crawl_cache import is_stale, nvd_start_date, nvd_record_count

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_SLEEP = 0.6   # seconds between requests (NVD enforces 5 req/30s without API key)
NVD_CACHE_MAX_AGE_HOURS = 24

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH":     "High",
    "MEDIUM":   "Medium",
    "LOW":      "Low",
}


# ── NVD parsers ────────────────────────────────────────────────────────────────

def extract_cwe(cve_data: dict) -> str:
    for w in cve_data.get("weaknesses", []):
        for d in w.get("description", []):
            if d["lang"] == "en" and d["value"].startswith("CWE-"):
                return d["value"]
    return ""


def extract_cvss(cve_data: dict) -> tuple[str, str]:
    metrics = cve_data.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics:
            data     = metrics[key][0]["cvssData"]
            score    = data.get("baseScore", "")
            severity = data.get("baseSeverity", "")
            return str(score), SEVERITY_MAP.get(severity.upper(), severity)
    return "", ""


def extract_cpe_tech(cve_data: dict) -> list[str]:
    tech = []
    for config in cve_data.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe   = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) > 4:
                    tech.append(parts[4])
    return list(set(tech))[:5]


def parse_record(item: dict) -> dict:
    cve    = item["cve"]
    cve_id = cve["id"]
    desc   = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "",
    )
    cwe_id            = extract_cwe(cve)
    cvss_score, sev   = extract_cvss(cve)
    affected_software = extract_cpe_tech(cve)
    references        = [r["url"] for r in cve.get("references", [])]

    return {
        "cve_id":             cve_id,
        "vulnerability_name": f"{cwe_id} vulnerability" if cwe_id else cve_id,
        "cwe_id":             cwe_id,
        "description":        desc,
        "cvss_score":         cvss_score,
        "cvss_severity":      sev,
        "affected_software":  affected_software,
        "published":          cve.get("published", ""),
        "references":         references[:5],
    }


# ── API fetch helpers ──────────────────────────────────────────────────────────

def fetch_nvd_page(params: dict) -> dict:
    """Fetch one page from NVD API. Raises on HTTP error."""
    resp = requests.get(NVD_API_URL, params=params, timeout=30)
    resp.raise_for_status()
    return resp.json()


def fetch_nvd_range(
    pub_start_date: str | None = None,
    pub_end_date:   str | None = None,
    max_results:    int        = 10_000,
    batch_size:     int        = 2_000,
) -> list[dict]:
    """
    Fetch CVE records from NVD, optionally filtered by publication date range.

    If pub_start_date is provided, fetches only CVEs published on/after that date.
    Otherwise fetches from the beginning (most recent first by NVD default).
    """
    all_records: list[dict] = []
    start_index = 0

    base_params: dict = {"resultsPerPage": batch_size}
    if pub_start_date:
        base_params["pubStartDate"] = pub_start_date
        print(f"  Incremental NVD fetch from: {pub_start_date}")
    if pub_end_date:
        base_params["pubEndDate"] = pub_end_date

    while True:
        params = {**base_params, "startIndex": start_index}
        try:
            data       = fetch_nvd_page(params)
            total_avail = data.get("totalResults", 0)
            vulns       = data.get("vulnerabilities", [])

            if not vulns:
                break

            for item in vulns:
                all_records.append(parse_record(item))

            start_index += len(vulns)
            fetched      = len(all_records)

            print(f"  Fetched {fetched:>6,} / {min(total_avail, max_results):,}", end="\r")

            if fetched >= max_results or start_index >= total_avail:
                break

            time.sleep(NVD_RATE_LIMIT_SLEEP)

        except Exception as exc:
            print(f"\n  ⚠️  NVD batch at startIndex={start_index} failed: {exc}")
            time.sleep(2)
            # Don't abort — return what we have so far
            break

    print(f"\n  NVD fetch complete: {len(all_records):,} records")
    return all_records


# ── Merge helpers ──────────────────────────────────────────────────────────────

def load_existing(path: Path) -> dict[str, dict]:
    """Load existing raw_nvd.json into a {cve_id: record} dict."""
    if not path.exists():
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            records = json.load(f)
        return {r["cve_id"]: r for r in records if r.get("cve_id")}
    except Exception as exc:
        print(f"  ⚠️  Could not load existing NVD cache: {exc}")
        return {}


def merge_and_save(existing: dict[str, dict], new_records: list[dict], path: Path) -> int:
    """
    Merge new_records into existing dict (new wins on conflict), save to path.
    Returns total record count after merge.
    """
    for rec in new_records:
        cve_id = rec.get("cve_id")
        if cve_id:
            existing[cve_id] = rec   # new record overwrites (may have updated CVSS etc.)

    all_records = list(existing.values())
    with open(path, "w", encoding="utf-8") as f:
        json.dump(all_records, f, indent=2, ensure_ascii=False)

    return len(all_records)


# ── Main ───────────────────────────────────────────────────────────────────────

def run(total: int = 10_000, batch: int = 2_000, out: str = "data/raw_nvd.json"):
    out_path = Path(out)

    # ── Cache check ────────────────────────────────────────────────────────
    existing_count = nvd_record_count(out_path)
    need_more = (total > existing_count * 1.1)  # user wants significantly more

    if not need_more and not is_stale(out_path, max_age_hours=NVD_CACHE_MAX_AGE_HOURS):
        print(f"  ✅ NVD cache is fresh (< {NVD_CACHE_MAX_AGE_HOURS}h old) — "
              f"skipping fetch ({existing_count:,} records on disk)")
        return

    existing = load_existing(out_path)
    existing_count = len(existing)

    # ── Incremental or full fetch ──────────────────────────────────────────
    # If user requested MORE records than we have cached → full fetch
    need_full_fetch = need_more

    if existing_count > 0 and not need_full_fetch:
        start_date = nvd_start_date(out_path, lookback_days=7)
        if start_date:
            print(f"  Incremental NVD fetch — {existing_count:,} records already cached")
            new_records = fetch_nvd_range(
                pub_start_date=start_date,
                max_results=total,
                batch_size=batch,
            )
        else:
            print(f"  Could not determine start date — doing full fetch")
            new_records = fetch_nvd_range(max_results=total, batch_size=batch)
    else:
        if need_full_fetch and existing_count > 0:
            print(f"  Scaling up: {existing_count:,} cached but {total:,} requested — full fetch")
        else:
            print(f"  No existing cache — doing full fetch ({total:,} records)")
        new_records = fetch_nvd_range(max_results=total, batch_size=batch)

    # ── Merge and save ─────────────────────────────────────────────────────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    total_saved = merge_and_save(existing, new_records, out_path)

    added = total_saved - existing_count
    print(f"  +{added:,} new CVEs merged  →  {total_saved:,} total records")
    print(f"\n✅ Saved {total_saved:,} NVD records → {out_path}")


if __name__ == "__main__":
    run()