"""
cluster_kev_campaigns.py  (FIXED)
─────────────────────────────────────────────────────────────────────────────
Fix: robust field reading that handles both CISA's native JSON field names
(cveID, dateAdded, knownRansomwareCampaignUse, vendorProject) AND the
pipeline's custom snake_case names (cve_id, date_added, ransomware_use, vendor).
─────────────────────────────────────────────────────────────────────────────
Output → data/raw_kev_clusters.json
"""

import json
import logging
from collections import defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

DATA_DIR         = Path("data")
KEV_FILE         = DATA_DIR / "raw_cisa_kev.json"
CWE_FILE         = DATA_DIR / "raw_cwe_chains.json"
OUT_FILE         = DATA_DIR / "raw_kev_clusters.json"

MIN_CLUSTER_SIZE = 2
TEMPORAL_CONF    = 0.70
RANSOMWARE_CONF  = 0.65
VENDOR_CONF      = 0.60
CWE_BOOST        = 0.10

VENDOR_STACK_MAP = {
    "apache":     "java_enterprise",
    "oracle":     "java_enterprise",
    "red hat":    "java_enterprise",
    "ibm":        "java_enterprise",
    "microsoft":  "microsoft_stack",
    "cisco":      "network_infrastructure",
    "fortinet":   "network_infrastructure",
    "palo alto":  "network_infrastructure",
    "f5":         "network_infrastructure",
    "juniper":    "network_infrastructure",
    "pulse":      "network_infrastructure",
    "ivanti":     "network_infrastructure",
    "wordpress":  "php_cms",
    "drupal":     "php_cms",
    "joomla":     "php_cms",
    "vmware":     "cloud_virtualisation",
    "docker":     "cloud_virtualisation",
    "kubernetes": "cloud_virtualisation",
    "atlassian":  "devops_tools",
    "gitlab":     "devops_tools",
    "jenkins":    "devops_tools",
    "elastic":    "logging_observability",
    "splunk":     "logging_observability",
}


# ─────────────────────────────────────────────────────────────────────────────
# Robust field getters — try all known field name variants
# ─────────────────────────────────────────────────────────────────────────────

def get_cve_id(r):
    """Try every known field name for CVE ID."""
    for f in ("cveID", "cve_id", "cve", "id", "CVE_ID", "vulnerability_id"):
        v = r.get(f, "")
        if v and str(v).startswith("CVE-"):
            return str(v)
    return ""


def get_date_added(r):
    """Try every known field name for date added."""
    for f in ("dateAdded", "date_added", "published", "date_published",
              "added_date", "addedDate", "published_date"):
        v = r.get(f, "")
        if v:
            return str(v)
    return ""


def get_ransomware_flag(r):
    """Return True if this CVE is known ransomware-associated."""
    # CISA native: knownRansomwareCampaignUse = "Known" | "Unknown"
    v1 = str(r.get("knownRansomwareCampaignUse", "")).strip().lower()
    if v1 == "known":
        return True
    # Pipeline custom: ransomware_use, ransomware_campaign, ransomware = True/False/"Known"
    for f in ("ransomware_use", "ransomware_campaign", "ransomware",
              "known_ransomware", "ransomwareCampaignUse"):
        v = r.get(f)
        if v is True:
            return True
        if isinstance(v, str) and v.lower() in ("known", "true", "yes"):
            return True
    return False


def get_vendor(r):
    """Try every known field name for vendor/project."""
    for f in ("vendorProject", "vendor_project", "vendor", "manufacturer",
              "vendorName", "vendor_name", "company"):
        v = r.get(f, "")
        if v:
            return str(v).lower().strip()
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Load
# ─────────────────────────────────────────────────────────────────────────────

def load_kev(path):
    with open(path) as f:
        raw = json.load(f)

    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        # Try common wrapper keys
        for key in ("vulnerabilities", "records", "data", "items", "cves"):
            if key in raw and isinstance(raw[key], list):
                records = raw[key]
                break
        else:
            # Maybe the dict itself contains CVE records keyed by CVE ID
            records = list(raw.values()) if raw else []
    else:
        records = []

    # DEBUG: show first record to verify field names
    if records:
        log.info(f"  Sample KEV record keys: {list(records[0].keys())[:10]}")

    log.info(f"  KEV records loaded: {len(records):,}")
    return records


def load_cwe_pairs(path):
    pairs = set()
    if not path.exists():
        return pairs
    with open(path) as f:
        data = json.load(f)
    for chain in data.get("cve_chains", []):
        a = chain.get("trigger_cve", "")
        b = chain.get("related_cve", "")
        if a and b:
            pairs.add((a, b))
            pairs.add((b, a))
    log.info(f"  CWE chain pairs loaded: {len(pairs):,}")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Clustering
# ─────────────────────────────────────────────────────────────────────────────

def temporal_clusters(records):
    dated = []
    for r in records:
        cve      = get_cve_id(r)
        raw_date = get_date_added(r)
        if not cve or not raw_date:
            continue
        # Try multiple date formats
        dt = None
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
            try:
                dt = datetime.strptime(raw_date[:len(fmt.replace('%Y','0000').replace('%m','00').replace('%d','00'))], fmt)
                break
            except ValueError:
                continue
        if dt is None:
            # Try just the first 10 chars as YYYY-MM-DD
            try:
                dt = datetime.strptime(raw_date[:10], "%Y-%m-%d")
            except ValueError:
                continue
        iso  = dt.isocalendar()
        week = f"{iso[0]}-W{iso[1]:02d}"
        dated.append((week, cve))

    week_buckets = defaultdict(list)
    for week, cve in dated:
        week_buckets[week].append(cve)

    clusters = []
    for week, cves in sorted(week_buckets.items()):
        cves = [c for c in cves if c]
        if len(cves) < MIN_CLUSTER_SIZE:
            continue
        clusters.append({
            "cluster_id":   f"week_{week}",
            "week":         week,
            "cves":         cves,
            "cluster_type": "temporal",
            "confidence":   TEMPORAL_CONF,
            "notes":        "CISA KEV batch — same campaign advisory window",
        })

    log.info(f"  Temporal clusters: {len(clusters):,}  (CVEs with parseable dates: {len(dated):,})")
    return clusters


def ransomware_cluster(records):
    rw_cves = [get_cve_id(r) for r in records if get_ransomware_flag(r) and get_cve_id(r)]
    log.info(f"  Ransomware-associated CVEs: {len(rw_cves):,}")
    return {
        "cves":         rw_cves,
        "confidence":   RANSOMWARE_CONF,
        "cluster_type": "ransomware",
        "notes":        "All actively weaponised in ransomware campaigns",
    }


def vendor_clusters(records):
    stack_buckets = defaultdict(list)
    for r in records:
        cve    = get_cve_id(r)
        vendor = get_vendor(r)
        if not cve:
            continue
        stack = None
        for k, v in VENDOR_STACK_MAP.items():
            if k in vendor:
                stack = v
                break
        if stack is None:
            stack = f"vendor_{vendor.replace(' ', '_')[:30]}" if vendor else "vendor_unknown"
        stack_buckets[stack].append(cve)

    clusters = []
    for stack, cves in stack_buckets.items():
        cves = list(set(cves))
        if len(cves) < MIN_CLUSTER_SIZE:
            continue
        clusters.append({
            "cluster_id":   f"vendor_{stack}",
            "stack":        stack,
            "cves":         cves,
            "cluster_type": "vendor_stack",
            "confidence":   VENDOR_CONF,
            "notes":        f"Same vendor stack: {stack}",
        })

    log.info(f"  Vendor/stack clusters: {len(clusters):,}")
    return clusters


def flatten_to_pairs(t_clust, rw_clust, v_clust, cwe_pairs):
    pairs = []
    seen  = set()

    def add(a, b, source, conf, extra=None):
        key = tuple(sorted([a, b]))
        if key in seen:
            return
        seen.add(key)
        cwe_boost = CWE_BOOST if (a, b) in cwe_pairs else 0.0
        entry = {
            "cve_a":              a,
            "cve_b":              b,
            "source":             source,
            "confidence":         round(min(conf + cwe_boost, 1.0), 3),
            "cwe_chain_confirms": cwe_boost > 0,
        }
        if extra:
            entry.update(extra)
        pairs.append(entry)

    for c in t_clust:
        for a, b in combinations(c["cves"], 2):
            add(a, b, "temporal_cluster", TEMPORAL_CONF,
                {"week": c["week"], "reason": f"Same KEV batch week {c['week']}"})

    rw = rw_clust["cves"]
    for a, b in combinations(rw[:200], 2):
        add(a, b, "ransomware_cluster", RANSOMWARE_CONF,
            {"reason": "Both confirmed weaponised in ransomware campaigns"})

    for c in v_clust:
        for a, b in combinations(c["cves"], 2):
            add(a, b, "vendor_stack_cluster", VENDOR_CONF,
                {"stack": c["stack"], "reason": f"Same technology stack: {c['stack']}"})

    log.info(f"  Total co-occurrence pairs: {len(pairs):,}")
    return pairs


def main():
    records   = load_kev(KEV_FILE)
    cwe_pairs = load_cwe_pairs(CWE_FILE)

    t_clusters = temporal_clusters(records)
    rw_cluster = ransomware_cluster(records)
    v_clusters = vendor_clusters(records)
    pairs      = flatten_to_pairs(t_clusters, rw_cluster, v_clusters, cwe_pairs)

    out = {
        "temporal_clusters":  t_clusters,
        "ransomware_cluster": rw_cluster,
        "vendor_clusters":    v_clusters,
        "cooccurrence_pairs": pairs,
        "stats": {
            "temporal_clusters":  len(t_clusters),
            "vendor_clusters":    len(v_clusters),
            "ransomware_cves":    len(rw_cluster["cves"]),
            "total_pairs":        len(pairs),
            "cwe_boosted_pairs":  sum(1 for p in pairs if p.get("cwe_chain_confirms")),
        },
    }

    with open(OUT_FILE, "w") as f:
        json.dump(out, f, indent=2)

    log.info(f"\n✅ KEV clusters saved → {OUT_FILE}")
    log.info(f"   Temporal clusters: {len(t_clusters):,}")
    log.info(f"   Vendor clusters:   {len(v_clusters):,}")
    log.info(f"   Total pairs:       {len(pairs):,}")


if __name__ == "__main__":
    main()