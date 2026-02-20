"""
collect_cwe_chains.py  (FIXED)
─────────────────────────────────────────────────────────────────────────────
Fix: robust CWE field reading from vuln_dataset.jsonl.
Handles NVD API v2 format, NVD API v1 format, and pipeline custom formats.
─────────────────────────────────────────────────────────────────────────────
Output → data/raw_cwe_chains.json
"""

import json
import zipfile
import io
import logging
import re
from collections import defaultdict
from pathlib import Path

import requests
from lxml import etree

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NVD_FILE    = DATA_DIR / "vuln_dataset.jsonl"
OUT_FILE    = DATA_DIR / "raw_cwe_chains.json"

REL_SEMANTICS = {
    "CanPrecede":  ("forward",  0.80),
    "CanFollow":   ("backward", 0.70),
    "ChildOf":     ("taxonomy", 0.60),
    "ParentOf":    ("taxonomy", 0.60),
    "Requires":    ("forward",  0.85),
    "RequiredBy":  ("backward", 0.85),
    "PeerOf":      ("lateral",  0.50),
    "MemberOf":    ("taxonomy", 0.40),
}


# ─────────────────────────────────────────────────────────────────────────────
# CWE XML parsing (unchanged — this part worked fine)
# ─────────────────────────────────────────────────────────────────────────────

def download_cwe_xml():
    log.info("Downloading CWE XML from MITRE …")
    r = requests.get(CWE_XML_URL, timeout=60)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        return zf.read(xml_name)


def parse_cwe_xml(xml_bytes):
    root = etree.fromstring(xml_bytes)
    ns   = {"cwe": "http://cwe.mitre.org/cwe-7"}
    cwe_meta = {}
    raw_rels  = []

    for w in root.findall(".//cwe:Weakness", ns):
        cid  = f"CWE-{w.get('ID')}"
        name = w.get("Name", "")
        desc_el = w.find(".//cwe:Description", ns)
        desc = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
        cwe_meta[cid] = {"name": name, "description": desc[:300], "type": "Weakness"}

        for rel in w.findall(".//cwe:Related_Weakness", ns):
            rel_type = rel.get("Nature", "")
            target   = f"CWE-{rel.get('CWE_ID', '')}"
            if rel_type in REL_SEMANTICS and target != cid:
                raw_rels.append({"from": cid, "to": target, "rel_type": rel_type})

    for c in root.findall(".//cwe:Category", ns):
        cid = f"CWE-{c.get('ID')}"
        if cid not in cwe_meta:
            cwe_meta[cid] = {"name": c.get("Name", ""), "description": "", "type": "Category"}

    log.info(f"  Parsed {len(cwe_meta):,} CWE entries, {len(raw_rels):,} raw relationships")
    return cwe_meta, raw_rels


def build_relationship_table(raw_rels, cwe_meta):
    enriched = []
    for r in raw_rels:
        sem = REL_SEMANTICS.get(r["rel_type"])
        if not sem:
            continue
        direction, confidence = sem
        enriched.append({
            "from_cwe":   r["from"],
            "to_cwe":     r["to"],
            "rel_type":   r["rel_type"],
            "direction":  direction,
            "confidence": confidence,
            "from_name":  cwe_meta.get(r["from"], {}).get("name", ""),
            "to_name":    cwe_meta.get(r["to"],   {}).get("name", ""),
        })
    log.info(f"  Enriched relationships: {len(enriched):,}")
    return enriched


def build_precede_graph(enriched_rels):
    graph = defaultdict(list)
    for r in enriched_rels:
        if r["rel_type"] in ("CanPrecede", "Requires"):
            graph[r["from_cwe"]].append(
                (r["to_cwe"], r["confidence"], [r["from_cwe"], r["to_cwe"]])
            )
    # 2-hop
    two_hop = defaultdict(list)
    for src, targets in graph.items():
        for mid, c1, path1 in targets:
            for dst, c2, _ in graph.get(mid, []):
                if dst != src:
                    two_hop[src].append((dst, round(c1 * c2, 3), path1 + [dst]))
    for src, items in two_hop.items():
        graph[src].extend(items)
    return dict(graph)


# ─────────────────────────────────────────────────────────────────────────────
# FIXED: robust CWE extraction from vuln_dataset.jsonl
# ─────────────────────────────────────────────────────────────────────────────

CWE_PATTERN = re.compile(r"CWE-\d+")


def extract_cwes_from_record(rec):
    """
    Try every known schema variant to extract CWE IDs from a NVD/pipeline record.
    Returns list of CWE ID strings like ["CWE-89", "CWE-79"].
    """
    found = set()

    def scan(obj):
        """Recursively scan any string/list/dict for CWE patterns."""
        if isinstance(obj, str):
            for m in CWE_PATTERN.findall(obj):
                if m != "CWE-noinfo" and m != "CWE-Other":
                    found.add(m)
        elif isinstance(obj, list):
            for item in obj:
                scan(item)
        elif isinstance(obj, dict):
            for v in obj.values():
                scan(v)

    # ── Try specific known field paths first (fast path) ──────────────────

    # NVD API v2 format:
    # weaknesses: [{type, source, description: [{lang, value: "CWE-89"}]}]
    for w in rec.get("weaknesses", []):
        if isinstance(w, dict):
            for desc in w.get("description", []):
                val = desc.get("value", "") if isinstance(desc, dict) else ""
                scan(val)

    # NVD API v1 / old format:
    # cve.problemtype.problemtype_data[].description[].value
    pt = rec.get("cve", {})
    if isinstance(pt, dict):
        scan(pt.get("problemtype", {}))

    # Pipeline custom flat fields
    for field in ("cwe", "cwe_id", "cwe_ids", "cwe_list", "weakness",
                  "problem_type", "problemtype", "weakness_type"):
        scan(rec.get(field))

    # ── Fallback: scan the entire record (catches any layout) ─────────────
    if not found:
        # Only scan fields likely to have CWE data — avoid huge text fields
        for field in ("weaknesses", "cwe", "cwe_id", "problemtype",
                      "vulnerability_type", "tags", "categories"):
            scan(rec.get(field))

    return list(found)


def load_cve_to_cwe(nvd_file):
    mapping   = {}
    total     = 0
    with_cwes = 0
    sample_shown = False

    if not nvd_file.exists():
        log.warning(f"  {nvd_file} not found")
        return mapping

    with open(nvd_file) as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1

            cve = (rec.get("cve_id") or rec.get("id") or
                   rec.get("cveId") or rec.get("CVE_ID") or "")
            if not cve:
                # Try nested: rec.cve.id
                cve_obj = rec.get("cve", {})
                if isinstance(cve_obj, dict):
                    cve = cve_obj.get("id", "")
            if not cve:
                continue

            cwes = extract_cwes_from_record(rec)
            if cwes:
                mapping[cve] = cwes
                with_cwes += 1
                # Show first matched record for debugging
                if not sample_shown:
                    log.info(f"  Sample CVE with CWE: {cve} → {cwes}")
                    sample_shown = True

    log.info(f"  Records scanned: {total:,}  |  CVEs with CWE: {with_cwes:,}")

    # If still 0 — do a deep scan on first 5 records to show what fields exist
    if with_cwes == 0:
        log.warning("  ⚠️  No CWE mappings found. Showing first record structure:")
        with open(nvd_file) as f:
            for i, line in enumerate(f):
                if i >= 3: break
                try:
                    rec = json.loads(line)
                    log.warning(f"  Record {i+1} keys: {list(rec.keys())}")
                    # Show any field that might contain CWE data
                    for k, v in rec.items():
                        s = str(v)
                        if "cwe" in k.lower() or "weakness" in k.lower() or "CWE" in s:
                            log.warning(f"    Field '{k}': {str(v)[:200]}")
                except: pass

    return mapping


# ─────────────────────────────────────────────────────────────────────────────
# CVE chain join (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def build_cve_chains(cve_to_cwe, precede_graph):
    cwe_to_cves = defaultdict(list)
    for cve, cwes in cve_to_cwe.items():
        for cwe in cwes:
            cwe_to_cves[cwe].append(cve)

    chains = []
    seen   = set()

    for trigger_cve, trigger_cwes in cve_to_cwe.items():
        for t_cwe in trigger_cwes:
            for (r_cwe, confidence, path) in precede_graph.get(t_cwe, []):
                for related_cve in cwe_to_cves.get(r_cwe, []):
                    if related_cve == trigger_cve:
                        continue
                    key = (trigger_cve, related_cve, r_cwe)
                    if key in seen:
                        continue
                    seen.add(key)
                    chains.append({
                        "trigger_cve":  trigger_cve,
                        "trigger_cwe":  t_cwe,
                        "related_cve":  related_cve,
                        "related_cwe":  r_cwe,
                        "chain_type":   "CanPrecede",
                        "confidence":   confidence,
                        "chain_path":   path,
                    })

    log.info(f"  CVE chains generated: {len(chains):,}")
    return chains


def main():
    xml_bytes      = download_cwe_xml()
    cwe_meta, raw  = parse_cwe_xml(xml_bytes)
    enriched       = build_relationship_table(raw, cwe_meta)
    precede_graph  = build_precede_graph(enriched)
    cve_to_cwe     = load_cve_to_cwe(NVD_FILE)
    cve_chains     = build_cve_chains(cve_to_cwe, precede_graph)

    out = {
        "cwe_relationships": enriched,
        "cve_chains":        cve_chains,
        "cwe_metadata":      cwe_meta,
        "stats": {
            "total_cwes":          len(cwe_meta),
            "total_relationships": len(enriched),
            "cves_with_cwe":       len(cve_to_cwe),
            "cve_chains":          len(cve_chains),
        },
    }

    with open(OUT_FILE, "w") as f:
        json.dump(out, f)

    log.info(f"\n✅ CWE chains saved → {OUT_FILE}")
    log.info(f"   CWE entries:       {len(cwe_meta):,}")
    log.info(f"   Relationships:     {len(enriched):,}")
    log.info(f"   CVEs with CWE:     {len(cve_to_cwe):,}")
    log.info(f"   CVE→CVE chains:    {len(cve_chains):,}")


if __name__ == "__main__":
    main()