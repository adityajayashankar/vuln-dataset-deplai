"""
build_dataset.py
----------------
Merges ALL raw source files into the full 6-layer schema.
Generates instruction-response training pairs for each layer.

DATA SOURCES:
  - raw_nvd.json:       NVD CVE database (open)
  - raw_epss.json:      FIRST EPSS exploit probability scores (open)
  - raw_github.json:    GitHub Security Advisories (open)
  - raw_blogs.json:     Security blog write-ups (open)
  - raw_papers.json:    arXiv, Semantic Scholar, OSV, IEEE papers (open + semi-closed)
  - raw_closed.json:    Full Disclosure, Bugtraq, HackerOne, MSRC, Vulners (closed)
  - raw_cisa_kev.json:  CISA KEV catalog — confirmed exploited CVEs (curated)
  - raw_exploitdb.json: Exploit-DB full CSV export — real exploit code (open)

Layers built:
  1. Vulnerability Intelligence  (OWASP Mapper + Correlation agents)
  2. Pentesting Intelligence      (Tool Selector + Scanner agents)
  3. Risk & Scoring               (Base Scorer + Severity Adjuster agents)
  4. Execution Context            (Tech Stack Filter + Spawn Decision agents)
  5. Audit Evidence               (Result Aggregator + Reporting agents)
  6. Remediation Learning         (Reflector + Memory agents)

FIX: owasp_mapper import — when running from repo root, the data/ directory
     is not automatically on the Python path. Added sys.path fix.
"""

import json
import re
import sys
import uuid
from pathlib import Path

# FIX: Ensure the data/ directory is on the path so owasp_mapper can be found
# regardless of whether the script is run from repo root or from data/
_data_dir = Path(__file__).parent
if str(_data_dir) not in sys.path:
    sys.path.insert(0, str(_data_dir))

from owasp_mapper import get_owasp_category, get_pentest_intel  # noqa: E402 (after path fix)


# ── Helpers ────────────────────────────────────────────────────────────────

def clean(text: str) -> str:
    if not text:
        return ""
    text = re.sub(r'\s+', ' ', str(text))
    text = re.sub(r'[^\x00-\x7F]+', '', text)
    return text.strip()


def risk_level(cvss_score) -> str:
    if not cvss_score:
        return "Unknown"
    try:
        s = float(cvss_score)
        if s >= 9.0: return "Critical"
        if s >= 7.0: return "High"
        if s >= 4.0: return "Medium"
        return "Low"
    except (ValueError, TypeError):
        return "Unknown"


def business_impact(owasp_cat: str) -> str:
    impacts = {
        "A01:2021-Broken Access Control":           "Unauthorized data access, privilege escalation",
        "A02:2021-Cryptographic Failures":          "Sensitive data exposure, credential theft",
        "A03:2021-Injection":                       "Database compromise, remote code execution",
        "A04:2021-Insecure Design":                 "Systematic security bypass, reputational damage",
        "A05:2021-Security Misconfiguration":       "System compromise via exposed attack surface",
        "A06:2021-Vulnerable and Outdated Components": "Full system takeover via known exploits",
        "A07:2021-Identification and Authentication Failures": "Account takeover, session hijacking",
        "A08:2021-Software and Data Integrity Failures": "Supply chain compromise, malicious updates",
        "A09:2021-Security Logging and Monitoring Failures": "Undetected breaches, delayed incident response",
        "A10:2021-Server-Side Request Forgery":     "Internal network access, cloud metadata theft",
    }
    return impacts.get(owasp_cat, "Security breach, data loss")


def infer_security_control_missing(owasp_cat: str) -> str:
    controls = {
        "A03:2021-Injection":                       "Input validation and parameterized queries",
        "A02:2021-Cryptographic Failures":          "Strong encryption and secure key management",
        "A01:2021-Broken Access Control":           "Authorization checks and role-based access control",
        "A07:2021-Identification and Authentication Failures": "MFA and strong session management",
        "A05:2021-Security Misconfiguration":       "Secure configuration baseline and hardening",
        "A06:2021-Vulnerable and Outdated Components": "Dependency scanning and patch management",
        "A10:2021-Server-Side Request Forgery":     "URL allowlist validation and network segmentation",
    }
    return controls.get(owasp_cat, "Security control review required")


# ── Load raw sources ───────────────────────────────────────────────────────

def load_json(path: str) -> list | dict:
    p = Path(path)
    if not p.exists():
        print(f"  ⚠️  {path} not found — skipping")
        return []
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def build_epss_lookup(epss_path: str) -> dict:
    raw = load_json(epss_path)
    return raw if isinstance(raw, dict) else {}


def build_github_lookup(github_path: str) -> dict[str, dict]:
    """
    Returns a dict keyed by EVERY identifier an advisory has:
      - primary cve_id       e.g. "CVE-2021-44228"
      - all entries in all_cve_ids  (alias list from identifiers field)
      - ghsa_id              e.g. "GHSA-jfh8-c2jp-hdp9"

    This means a single advisory can be found via any of its IDs.
    Previously only keyed by cve_id — dropped 2,951 GHSA-only advisories.
    """
    raw    = load_json(github_path)
    lookup = {}

    for item in raw:
        # Index by all CVE IDs (primary + aliases)
        all_cves = item.get("all_cve_ids", [])
        if not all_cves and item.get("cve_id"):
            all_cves = [item["cve_id"]]

        for cve_id in all_cves:
            if cve_id:
                lookup[cve_id] = item

        # Also index by GHSA ID — used in Pass 3 for GHSA-only entries
        ghsa_id = item.get("ghsa_id", "")
        if ghsa_id:
            lookup[ghsa_id] = item

    return lookup


def build_blog_lookup(blog_path: str) -> dict:
    raw = load_json(blog_path)
    lookup: dict[str, str] = {}
    for item in raw:
        content = item.get("content", "")[:3000]
        source  = f"Source: {item.get('url', 'Unknown Blog')}\n\n{content}"
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + source
    return lookup


def build_papers_lookup(papers_path: str) -> dict:
    raw = load_json(papers_path)
    lookup: dict[str, str] = {}
    for paper in raw:
        title    = paper.get("title", "Unknown Paper")
        abstract = paper.get("abstract", "")
        source   = paper.get("source", "research")
        fulltext = paper.get("fulltext_sample", "")
        content  = f"Research Paper [{source}]: {title}\n\n{abstract}"
        if fulltext:
            content += f"\n\nExcerpt: {fulltext[:1000]}"
        for cve in paper.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + content
    return lookup


def build_closed_sources_lookup(closed_path: str) -> dict:
    raw = load_json(closed_path)
    lookup: dict[str, str] = {}
    for item in raw:
        source_type = item.get("source", "unknown")
        title   = item.get("title", "")
        content = item.get("content", item.get("summary", item.get("body", item.get("description", ""))))[:1500]

        headers = {
            "full_disclosure":   f"Full Disclosure Mailing List:\n{content}",
            "bugtraq":           f"Bugtraq Mailing List:\n{content}",
            "hackerone":         f"HackerOne Report: {title}\nSeverity: {item.get('severity', 'N/A')}\n{content}",
            "microsoft_msrc":    f"Microsoft Security Advisory: {title}\n{content}",
            "reddit_netsec":     f"Reddit /r/netsec: {title}\nScore: {item.get('score', 0)}\n{content}",
            "cisa_kev":          (
                f"CISA KEV (Confirmed Exploited): {item.get('vulnerability_name', title)}\n"
                f"Product: {item.get('product', 'N/A')}\n"
                f"Required Action: {item.get('required_action', 'N/A')}\n"
                f"Ransomware: {item.get('known_ransomware', 'Unknown')}\n{content}"
            ),
        }
        header = headers.get(source_type, f"{source_type}: {content}")

        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup[cve] = lookup.get(cve, "") + ("\n\n---\n\n" if cve in lookup else "") + header
    return lookup


def build_kev_lookup(kev_path: str) -> dict:
    """
    Separate KEV lookup that preserves structured fields (not just text).
    Returns {cve_id: kev_record} for rich metadata access.
    """
    raw = load_json(kev_path)
    return {item["cve_id"]: item for item in raw if item.get("cve_id")}


def build_exploitdb_lookup(exploitdb_path: str) -> dict:
    """
    Returns {cve_id: list_of_exploit_records} so multiple exploits per CVE are kept.
    """
    raw    = load_json(exploitdb_path)
    lookup: dict[str, list] = {}
    for item in raw:
        for cve in item.get("cves_mentioned", []):
            cve = cve.upper()
            lookup.setdefault(cve, []).append(item)
    return lookup


# ── Build full schema record ───────────────────────────────────────────────

def build_record(
    nvd_rec:       dict,
    epss_map:      dict,
    github_map:    dict,
    blog_map:      dict,
    papers_map:    dict,
    closed_map:    dict,
    kev_map:       dict,
    exploitdb_map: dict,
) -> dict:
    cve_id = nvd_rec.get("cve_id", "")
    cwe_id = nvd_rec.get("cwe_id", "")
    desc   = clean(nvd_rec.get("description", ""))
    cvss   = nvd_rec.get("cvss_score", "")
    sev    = nvd_rec.get("cvss_severity", "")

    owasp_cat  = get_owasp_category(cwe_id)
    pentest    = get_pentest_intel(owasp_cat)
    epss_score = epss_map.get(cve_id, "")
    gh_advisory = github_map.get(cve_id, {})
    kev_entry  = kev_map.get(cve_id, {})
    exploits   = exploitdb_map.get(cve_id, [])

    fix_rec = gh_advisory.get("fix_recommendation", "")
    if not fix_rec and kev_entry.get("required_action"):
        fix_rec = f"CISA mandate: {kev_entry['required_action']}"
    if not fix_rec:
        fix_rec = "Apply vendor-supplied patches. Implement input validation and follow secure coding practices."

    # Combine all real-world context
    context_parts = [
        blog_map.get(cve_id, ""),
        papers_map.get(cve_id, ""),
        closed_map.get(cve_id, ""),
    ]
    if kev_entry:
        context_parts.append(
            f"CISA KEV (Confirmed Exploited in Wild):\n"
            f"  Product: {kev_entry.get('product', 'N/A')}\n"
            f"  Ransomware: {kev_entry.get('known_ransomware', 'Unknown')}\n"
            f"  Required action: {kev_entry.get('required_action', 'N/A')}\n"
            f"  Notes: {kev_entry.get('notes', '')}"
        )
    if exploits:
        exploit_summary = "; ".join([
            f"[{e.get('exploit_type', '?')}/{e.get('platform', '?')}] {e.get('description', '')[:100]}"
            for e in exploits[:3]
        ])
        context_parts.append(f"Exploit-DB Entries ({len(exploits)} exploits):\n{exploit_summary}")

    combined_context = "\n\n".join(filter(None, context_parts))

    # Source tracking
    sources = ["NVD + OWASP + FIRST EPSS"]
    if gh_advisory:     sources.append("GitHub Advisories")
    if blog_map.get(cve_id): sources.append("Security Blogs")
    if papers_map.get(cve_id): sources.append("Research Papers")
    if closed_map.get(cve_id): sources.append("Closed Sources")
    if kev_entry:       sources.append("CISA KEV")
    if exploits:        sources.append("Exploit-DB")

    return {
        "id": f"VULN_{str(uuid.uuid4())[:8].upper()}",

        # Layer 1: Vulnerability Intelligence
        "vulnerability_name":    nvd_rec.get("vulnerability_name", cve_id),
        "cve_id":                cve_id,
        "cwe_id":                cwe_id,
        "owasp_category":        owasp_cat,
        "description":           desc,
        "root_cause":            infer_security_control_missing(owasp_cat),
        "confirmed_exploited":   bool(kev_entry),   # CISA KEV = confirmed in wild

        # Layer 2: Pentesting Intelligence
        "attack_method":         pentest.get("attack_method", ""),
        "payload_example":       pentest.get("payload_example", ""),
        "detection_signals":     pentest.get("detection_signals", []),
        "real_world_exploit":    combined_context,
        "code_pattern":          pentest.get("code_pattern", ""),
        "exploit_count":         len(exploits),

        # Layer 3: Risk & Scoring
        "cvss_score":            cvss,
        "cvss_severity":         sev,
        "epss_score":            epss_score,
        "risk_level":            risk_level(cvss),
        "business_impact":       business_impact(owasp_cat),
        "kev_ransomware":        kev_entry.get("known_ransomware", "") if kev_entry else "",

        # Layer 4: Execution Context
        "asset_type":            "Web Application",
        "environment":           "Unknown",
        "internet_facing":       True,
        "tech_stack":            {"language": "", "framework": "", "database": ""},

        # Layer 5: Audit Evidence
        "tool_used":             pentest.get("tool_used", "Manual review"),
        "evidence_type":         "vulnerability_research",
        "evidence_summary":      f"Identified via CVE database. CVSS: {cvss}. {desc[:120]}...",
        "security_control_missing": infer_security_control_missing(owasp_cat),

        # Layer 6: Remediation Learning
        "fix_recommendation":    fix_rec,
        "status":                "Open",
        "related_vulnerabilities": [],

        "source": " + ".join(sources),
    }


# ── Generate training pairs ────────────────────────────────────────────────

def to_training_pairs(record: dict) -> list[dict]:
    cve    = record["cve_id"]
    desc   = record["description"]
    owasp  = record["owasp_category"]
    cvss   = record["cvss_score"]
    risk   = record["risk_level"]
    sev    = record["cvss_severity"]
    epss   = record["epss_score"]
    fix    = record["fix_recommendation"]
    method = record["attack_method"]
    sigs   = ", ".join(record["detection_signals"])
    biz    = record["business_impact"]
    ctrl   = record["security_control_missing"]
    tool   = record["tool_used"]
    cwe    = record["cwe_id"]
    exploit_ctx = record.get("real_world_exploit", "")
    kev_ransomware = record.get("kev_ransomware", "")
    confirmed_exploited = record.get("confirmed_exploited", False)

    pairs = []

    # L1: Vulnerability Intelligence
    if desc:
        pairs.append({
            "instruction": f"Explain the vulnerability {cve} and map it to its OWASP category.",
            "input":       "",
            "output":      f"{desc}\n\nOWASP Category: {owasp}\nCWE: {cwe}",
            "layer":       "vulnerability_intelligence",
            "agent":       "OWASP Mapper Agent"
        })

    # L2: Pentesting Intelligence
    if method:
        pairs.append({
            "instruction": "Describe how to test for this vulnerability during a pentest.",
            "input":       desc,
            "output":      (
                f"Attack Method: {method}\n\n"
                f"Detection Signals: {sigs}\n\n"
                f"Recommended Tool: {tool}"
            ),
            "layer":       "pentesting_intelligence",
            "agent":       "Tool Selector Agent"
        })

    # L2b: Real-world context (from research + closed sources + KEV + Exploit-DB)
    if exploit_ctx:
        pairs.append({
            "instruction": f"Provide real-world exploit examples and research findings for {cve}.",
            "input":       desc,
            "output":      f"Real-world context for {cve}:\n\n{exploit_ctx[:3000]}",
            "layer":       "pentesting_intelligence",
            "agent":       "Scanner Agent"
        })

    # L3: Risk & Scoring
    if cvss:
        kev_note = ""
        if confirmed_exploited:
            kev_note = f"\nCISA KEV: This CVE is CONFIRMED exploited in the wild."
            if kev_ransomware == "Known":
                kev_note += " Known ransomware campaign use."

        pairs.append({
            "instruction": "Perform a risk assessment for this vulnerability.",
            "input":       desc,
            "output":      (
                f"CVSS Score: {cvss} ({sev})\n"
                f"Risk Level: {risk}\n"
                f"EPSS Score: {epss if epss else 'Not available'}\n"
                f"Business Impact: {biz}"
                f"{kev_note}"
            ),
            "layer":       "risk_scoring",
            "agent":       "Base Scorer Agent"
        })

    # L4: Execution Context
    if owasp != "Unknown":
        pairs.append({
            "instruction": "Which security tool should be used to test this vulnerability, and why?",
            "input":       f"Vulnerability type: {owasp}\nDescription: {desc}",
            "output":      (
                f"Recommended tool: {tool}\n"
                f"Reason: This is a {owasp} class vulnerability. "
                f"The attack method involves: {method}"
            ),
            "layer":       "execution_context",
            "agent":       "Tool Selector Agent"
        })

    # L5: Audit Evidence
    if cvss:
        pairs.append({
            "instruction": "Generate an audit finding summary for this vulnerability.",
            "input":       desc,
            "output":      (
                f"Finding: {record['vulnerability_name']}\n"
                f"CVE: {cve} | CWE: {cwe} | OWASP: {owasp}\n"
                f"Severity: {sev} (CVSS {cvss})\n"
                f"Security Control Missing: {ctrl}\n"
                f"Evidence: Confirmed via vulnerability research and CVE database.\n"
                f"Tool: {tool}"
                + (f"\nCISA KEV: Actively exploited in wild." if confirmed_exploited else "")
            ),
            "layer":       "audit_evidence",
            "agent":       "Reporting Agent"
        })

    # L6: Remediation Learning
    if fix:
        pairs.append({
            "instruction": "What is the recommended remediation for this vulnerability?",
            "input":       desc,
            "output":      (
                f"Remediation: {fix}\n\n"
                f"Root Cause: {ctrl}\n"
                f"Control Type: Technical"
            ),
            "layer":       "remediation_learning",
            "agent":       "Reflector Agent"
        })

    return pairs


# ── Main ───────────────────────────────────────────────────────────────────

def run():
    print("Loading raw data sources...")
    nvd_records = load_json("data/raw_nvd.json")
    epss_map    = build_epss_lookup("data/raw_epss.json")
    github_map  = build_github_lookup("data/raw_github.json")
    blog_map    = build_blog_lookup("data/raw_blogs.json")
    papers_map  = build_papers_lookup("data/raw_papers.json")
    closed_map  = build_closed_sources_lookup("data/raw_closed.json")
    kev_map     = build_kev_lookup("data/raw_cisa_kev.json")
    exploitdb_map = build_exploitdb_lookup("data/raw_exploitdb.json")

    print(f"  NVD records:       {len(nvd_records)}")
    print(f"  EPSS entries:      {len(epss_map)}")
    print(f"  GitHub entries:    {len(github_map)}")
    print(f"  Blog CVE matches:  {len(blog_map)}")
    print(f"  Paper CVE matches: {len(papers_map)}")
    print(f"  Closed CVE matches:{len(closed_map)}")
    print(f"  CISA KEV entries:  {len(kev_map)}")
    print(f"  Exploit-DB CVEs:   {len(exploitdb_map)}")

    seen_cves      = set()
    full_records   = []
    training_pairs = []

    # ── Pass 1: NVD records (main loop) ───────────────────────────────────
    for nvd_rec in nvd_records:
        cve_id = nvd_rec.get("cve_id", "")
        desc   = nvd_rec.get("description", "")

        if not desc or len(desc) < 50:
            continue
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)

        record = build_record(
            nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))

    # ── Pass 2: CISA KEV entries not already covered by NVD batch ─────────
    # KEV has ~1,522 high-value confirmed-exploited CVEs. The NVD batch we
    # fetched may not include all of them (especially if NVD fetched old CVEs).
    # For each KEV entry not yet seen, build a minimal record directly from
    # KEV data so it ALWAYS appears in the training set.
    kev_only_count = 0
    for cve_id, kev_entry in kev_map.items():
        if cve_id in seen_cves:
            continue  # Already handled in Pass 1
        seen_cves.add(cve_id)

        # Build a minimal NVD-style record from KEV fields
        desc = kev_entry.get("description", "")
        if not desc:
            desc = (
                f"{kev_entry.get('vulnerability_name', cve_id)} affecting "
                f"{kev_entry.get('vendor', 'Unknown')} {kev_entry.get('product', '')}. "
                f"Actively exploited in the wild per CISA KEV catalog."
            )

        minimal_nvd_rec = {
            "cve_id":             cve_id,
            "vulnerability_name": kev_entry.get("vulnerability_name", cve_id),
            "cwe_id":             "",        # not in KEV data
            "description":        desc,
            "cvss_score":         "",        # not in KEV data directly
            "cvss_severity":      "",
            "affected_software":  [kev_entry.get("product", "")],
            "published":          kev_entry.get("date_added", ""),
        }

        record = build_record(
            minimal_nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        kev_only_count += 1

    print(f"  KEV-only records added (not in NVD batch): {kev_only_count}")

    # ── Pass 3: GHSA-only GitHub advisories (no CVE ID at all) ────────────
    # ~2,900 of 3,000 GitHub advisories have only a GHSA ID. They contain
    # real fix recommendations, affected packages, and severity data that
    # is valuable for the remediation_learning and audit_evidence layers.
    # We use the raw github JSON directly (not the lookup dict) to find them.
    raw_github     = load_json("data/raw_github.json")
    ghsa_only_count = 0

    for adv in raw_github:
        # Skip if this advisory already contributed via a CVE ID in Pass 1/2
        ghsa_id  = adv.get("ghsa_id", "")
        cve_ids  = adv.get("all_cve_ids", []) or ([adv["cve_id"]] if adv.get("cve_id") else [])

        already_seen = any(c in seen_cves for c in cve_ids) or ghsa_id in seen_cves
        if already_seen:
            continue

        # Only process entries with no CVE ID at all
        if cve_ids:
            continue

        if not ghsa_id:
            continue

        desc = adv.get("description", "") or adv.get("vulnerability_name", "")
        if not desc or len(desc) < 30:
            continue

        seen_cves.add(ghsa_id)

        # Build a minimal NVD-style record from the GHSA advisory
        # Use ghsa_id as the cve_id so the rest of the pipeline works unchanged
        cwe_ids = adv.get("cwe_ids", [])
        minimal_nvd_rec = {
            "cve_id":             ghsa_id,
            "vulnerability_name": adv.get("vulnerability_name", ghsa_id),
            "cwe_id":             cwe_ids[0] if cwe_ids else "",
            "description":        desc,
            "cvss_score":         adv.get("cvss_score", ""),
            "cvss_severity":      adv.get("cvss_severity", ""),
            "affected_software":  adv.get("affected_packages", [])[:5],
            "published":          adv.get("published", ""),
        }

        record = build_record(
            minimal_nvd_rec, epss_map, github_map, blog_map,
            papers_map, closed_map, kev_map, exploitdb_map
        )
        full_records.append(record)
        training_pairs.extend(to_training_pairs(record))
        ghsa_only_count += 1

    print(f"  GHSA-only records added (no CVE ID):        {ghsa_only_count}")

    # ── Save outputs ─────────────────────────────────────────────────────
    with open("data/vuln_dataset.jsonl", "w") as f:
        for r in full_records:
            f.write(json.dumps(r) + "\n")

    with open("data/training_pairs.jsonl", "w") as f:
        for p in training_pairs:
            f.write(json.dumps(p) + "\n")

    # ── Stats ─────────────────────────────────────────────────────────────
    layer_counts: dict[str, int] = {}
    for p in training_pairs:
        l = p.get("layer", "unknown")
        layer_counts[l] = layer_counts.get(l, 0) + 1

    github_matched = sum(1 for r in full_records if "GitHub Advisories" in r.get("source", ""))
    kev_records   = sum(1 for r in full_records if r.get("confirmed_exploited"))
    exploit_recs  = sum(1 for r in full_records if r.get("exploit_count", 0) > 0)
    paper_recs    = sum(1 for r in full_records if "Research Papers" in r.get("source", ""))
    closed_recs   = sum(1 for r in full_records if "Closed Sources" in r.get("source", ""))

    print(f"\n✅ Full schema records:  {len(full_records)} → data/vuln_dataset.jsonl")
    print(f"✅ Training pairs total: {len(training_pairs)} → data/training_pairs.jsonl")
    print("\nTraining pairs per layer:")
    for layer, count in sorted(layer_counts.items()):
        print(f"  {layer:<32} {count:>6} examples")

    print(f"\n📊 Source enrichment:")
    print(f"  GitHub advisories matched:      {github_matched}  (CVE + GHSA)")
    print(f"  CISA KEV (confirmed exploited): {kev_records}")
    print(f"  Records with Exploit-DB data:   {exploit_recs}")
    print(f"  Records with research papers:   {paper_recs}")
    print(f"  Records with closed sources:    {closed_recs}")


if __name__ == "__main__":
    run()