"""
build_cooccurrence_v2.py
─────────────────────────────────────────────────────────────────────────────
Replaces the original raw_cooccurrence.json builder.

Pulls together FOUR data sources:
  1. CWE chains         (data/raw_cwe_chains.json)       — semantic relationships
  2. KEV clusters       (data/raw_kev_clusters.json)      — campaign co-occurrence
  3. Stack profiles     (stack_profiles.py)               — expert knowledge
  4. NVD product data   (data/vuln_dataset.jsonl)         — product co-occurrence

Produces:
  data/raw_cooccurrence_v2.json   — rich model for pair generation
  (also overwrites data/raw_cooccurrence.json for backward compat)

Run:
  python build_cooccurrence_v2.py
"""

import json
import logging
from collections import defaultdict
from itertools import combinations
from pathlib import Path

from stack_profiles import STACK_PROFILES

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

DATA_DIR       = Path("data")
NVD_FILE       = DATA_DIR / "vuln_dataset.jsonl"
CWE_CHAIN_FILE = DATA_DIR / "raw_cwe_chains.json"
KEV_CLUSTER_FILE = DATA_DIR / "raw_kev_clusters.json"
OUT_V2         = DATA_DIR / "raw_cooccurrence_v2.json"
OUT_COMPAT     = DATA_DIR / "raw_cooccurrence.json"

# Confidence weights by source
SOURCE_WEIGHTS = {
    "attack_chain":       0.90,  # Expert-defined sequential exploit chains
    "remediation_tie":    0.85,  # Same patch closes both — structurally coupled
    "high_conf_same_stack": 0.75,
    "cwe_can_precede":    0.75,
    "cwe_can_follow":     0.65,
    "temporal_kev":       0.70,
    "ransomware_kev":     0.65,
    "vendor_kev":         0.60,
    "conditional_same_stack": 0.60,
    "product_cooccurrence": 0.45,
    "cwe_child_of":       0.40,
}


# ─────────────────────────────────────────────────────────────────────────────
# Loaders
# ─────────────────────────────────────────────────────────────────────────────

def load_jsonl(path):
    records = []
    if not path.exists():
        log.warning(f"  {path} not found")
        return records
    with open(path) as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def load_json(path):
    if not path.exists():
        log.warning(f"  {path} not found")
        return {}
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Source 1: Stack profile pairs
# ─────────────────────────────────────────────────────────────────────────────

def pairs_from_stack_profiles():
    pairs = []
    seen  = set()

    def add(a, b, source, conf, reason, profile_key, extra=None):
        key = (tuple(sorted([a, b])), source)
        if key in seen:
            return
        seen.add(key)
        entry = {
            "cve_a":       a,
            "cve_b":       b,
            "source":      source,
            "confidence":  conf,
            "reason":      reason,
            "profile":     profile_key,
        }
        if extra:
            entry.update(extra)
        pairs.append(entry)

    for pk, profile in STACK_PROFILES.items():
        display = profile.get("display_name", pk)
        hc = [x["cve"] for x in profile.get("high_confidence", [])]

        # Attack chains — highest confidence (ordered, directional)
        for chain in profile.get("attack_chains", []):
            for i in range(len(chain) - 1):
                a, b = chain[i], chain[i + 1]
                add(a, b, "attack_chain", SOURCE_WEIGHTS["attack_chain"],
                    f"Sequential exploit chain in {display}: {a} enables {b}",
                    pk, {"chain_position": i, "chain_length": len(chain)})

        # Remediation ties — patching one patches all
        for tie in profile.get("remediation_ties", []):
            fix = tie.get("fix", "")
            tie_cves = tie.get("cves", [])
            for a, b in combinations(tie_cves, 2):
                add(a, b, "remediation_tie", SOURCE_WEIGHTS["remediation_tie"],
                    f"Same fix: '{fix}' closes both — structurally coupled", pk,
                    {"fix": fix})

        # High-confidence same-stack pairs
        for a, b in combinations(hc, 2):
            add(a, b, "high_conf_same_stack", SOURCE_WEIGHTS["high_conf_same_stack"],
                f"Both high-confidence in {display} — co-present when stack confirmed", pk)

        # Conditional same-stack pairs
        cond_cves = []
        for cond_items in profile.get("conditional", {}).values():
            cond_cves.extend([x["cve"] for x in cond_items])
        for a in hc:
            for b in cond_cves:
                if a != b:
                    add(a, b, "conditional_same_stack",
                        SOURCE_WEIGHTS["conditional_same_stack"],
                        f"High-confidence {a} in {display} implies conditional surface includes {b}",
                        pk)

    log.info(f"  Stack profile pairs: {len(pairs):,}")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Source 2: CWE chain pairs
# ─────────────────────────────────────────────────────────────────────────────

def pairs_from_cwe_chains(cwe_data):
    pairs = []
    seen  = set()

    for chain in cwe_data.get("cve_chains", []):
        a    = chain.get("trigger_cve", "")
        b    = chain.get("related_cve", "")
        conf = chain.get("confidence", 0.5)
        path = chain.get("chain_path", [])
        if not a or not b or a == b:
            continue
        key = tuple(sorted([a, b]))
        if key in seen:
            continue
        seen.add(key)
        pairs.append({
            "cve_a":       a,
            "cve_b":       b,
            "source":      "cwe_can_precede",
            "confidence":  conf,
            "reason":      f"CWE chain: {' → '.join(path)} — {a} creates conditions enabling {b}",
            "cwe_path":    path,
        })

    log.info(f"  CWE chain pairs: {len(pairs):,}")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Source 3: KEV cluster pairs
# ─────────────────────────────────────────────────────────────────────────────

def pairs_from_kev_clusters(kev_data):
    pairs = kev_data.get("cooccurrence_pairs", [])

    # Remap source labels to our standard
    source_map = {
        "temporal_cluster":     "temporal_kev",
        "ransomware_cluster":   "ransomware_kev",
        "vendor_stack_cluster": "vendor_kev",
    }
    for p in pairs:
        p["source"] = source_map.get(p.get("source", ""), p.get("source", "unknown_kev"))

    log.info(f"  KEV cluster pairs: {len(pairs):,}")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Source 4: NVD product co-occurrence
# ─────────────────────────────────────────────────────────────────────────────

def pairs_from_nvd_products(nvd_records, max_per_product=20):
    """CVEs affecting the exact same CPE product string often co-occur."""
    product_to_cves = defaultdict(list)

    for rec in nvd_records:
        cve = rec.get("cve_id") or rec.get("id", "")
        if not cve:
            continue
        # Collect CPE product strings from multiple possible schema locations
        cpes = set()
        for field in ("cpe", "cpes", "configurations", "affected_products"):
            val = rec.get(field)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, str) and item.startswith("cpe:"):
                        # Normalise: take vendor:product portion only
                        parts = item.split(":")
                        if len(parts) >= 5:
                            cpes.add(f"{parts[3]}:{parts[4]}")
                    elif isinstance(item, dict):
                        cpe_str = item.get("cpe23Uri", item.get("cpe", ""))
                        if cpe_str:
                            parts = cpe_str.split(":")
                            if len(parts) >= 5:
                                cpes.add(f"{parts[3]}:{parts[4]}")
            elif isinstance(val, str) and val.startswith("cpe:"):
                parts = val.split(":")
                if len(parts) >= 5:
                    cpes.add(f"{parts[3]}:{parts[4]}")

        for prod in cpes:
            product_to_cves[prod].append(cve)

    pairs = []
    seen  = set()
    for prod, cves in product_to_cves.items():
        cves = list(set(cves))
        if len(cves) < 2:
            continue
        # Cap to avoid combinatorial explosion for very popular products
        cves = cves[:max_per_product]
        for a, b in combinations(cves, 2):
            key = tuple(sorted([a, b]))
            if key in seen:
                continue
            seen.add(key)
            pairs.append({
                "cve_a":      a,
                "cve_b":      b,
                "source":     "product_cooccurrence",
                "confidence": SOURCE_WEIGHTS["product_cooccurrence"],
                "reason":     f"Both affect same CPE product: {prod}",
                "product":    prod,
            })

    log.info(f"  NVD product co-occurrence pairs: {len(pairs):,}")
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Merge + deduplicate (keep highest-confidence version of each pair)
# ─────────────────────────────────────────────────────────────────────────────

def merge_pairs(*sources):
    best = {}   # canonical_key → pair dict
    for source in sources:
        for pair in source:
            a    = pair.get("cve_a", "")
            b    = pair.get("cve_b", "")
            conf = pair.get("confidence", 0.0)
            if not a or not b:
                continue
            key = tuple(sorted([a, b]))
            if key not in best or best[key]["confidence"] < conf:
                best[key] = pair

    merged = list(best.values())
    log.info(f"  Merged total unique pairs: {len(merged):,}")
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# Build negative inference registry from stack profiles
# ─────────────────────────────────────────────────────────────────────────────

def build_negative_registry():
    """
    Returns list of negative inference rules used by the pair generator.
    Each rule: {trigger_condition, absent_cves, still_assess, reason, profile}
    """
    rules = []
    for pk, profile in STACK_PROFILES.items():
        for rule in profile.get("negative_rules", []):
            rules.append({
                "profile":     pk,
                "display":     profile.get("display_name", pk),
                "condition":   rule.get("condition", ""),
                "absent_cves": rule.get("absent_cves", []),
                "still_assess": rule.get("still_assess", []),
                "reason":      rule.get("reason", ""),
            })
    log.info(f"  Negative inference rules: {len(rules):,}")
    return rules


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    log.info("Loading data sources …")
    nvd_records = load_jsonl(NVD_FILE)
    log.info(f"  NVD records: {len(nvd_records):,}")

    cwe_data = load_json(CWE_CHAIN_FILE)
    log.info(f"  CWE chains loaded: {len(cwe_data.get('cve_chains', [])):,}")

    kev_data = load_json(KEV_CLUSTER_FILE)
    log.info(f"  KEV pairs loaded: {len(kev_data.get('cooccurrence_pairs', [])):,}")

    log.info("Building co-occurrence pairs from each source …")
    stack_pairs   = pairs_from_stack_profiles()
    cwe_pairs     = pairs_from_cwe_chains(cwe_data)
    kev_pairs     = pairs_from_kev_clusters(kev_data)
    product_pairs = pairs_from_nvd_products(nvd_records)

    all_pairs     = merge_pairs(stack_pairs, cwe_pairs, kev_pairs, product_pairs)
    neg_registry  = build_negative_registry()

    # Source breakdown
    by_source = defaultdict(int)
    for p in all_pairs:
        by_source[p.get("source", "unknown")] += 1

    out = {
        "cooccurrence_pairs": all_pairs,
        "negative_rules":     neg_registry,
        "stack_profiles":     list(STACK_PROFILES.keys()),
        "stats": {
            "total_pairs":         len(all_pairs),
            "negative_rules":      len(neg_registry),
            "by_source":           dict(by_source),
            "stack_profiles":      len(STACK_PROFILES),
            "cwe_chain_pairs":     len(cwe_pairs),
            "kev_pairs":           len(kev_pairs),
            "stack_pairs":         len(stack_pairs),
            "product_pairs":       len(product_pairs),
        },
    }

    with open(OUT_V2, "w") as f:
        json.dump(out, f)

    # Backward-compat overwrite
    with open(OUT_COMPAT, "w") as f:
        json.dump(out, f)

    log.info(f"\n✅ Co-occurrence v2 saved → {OUT_V2}")
    log.info(f"   Total pairs:      {len(all_pairs):,}")
    log.info(f"   Negative rules:   {len(neg_registry):,}")
    log.info("\n   By source:")
    for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
        log.info(f"     {src:35s}  {count:,}")


if __name__ == "__main__":
    main()