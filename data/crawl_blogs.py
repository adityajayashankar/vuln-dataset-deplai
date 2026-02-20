"""
crawl_blogs.py  —  Fully agentic vulnerability intelligence crawler
---------------------------------------------------------------------
Outputs raw_blogs.json structured for the correlation/co-occurrence pipeline.

The LLM drives the ENTIRE discovery process — no hardcoded topics or websites:
  Phase 1: LLM plans search strategy           (1 LLM call → 20-30 queries)
  Phase 2: Tavily discovers URLs                (parallel searches)
  Phase 3: Dynamic discovery                    (Vulhub + NVD refs, no LLM)
  Phase 4: crawl4ai deep crawl                  (concurrent, semaphore-controlled)
  Phase 5: Link harvesting from crawled pages   (follow CVE-rich URLs in content)
  Phase 6: LLM gap analysis → Round 2 queries   (1 LLM call)
  Phase 7: Round 2 discover + crawl
  Phase 8: Structured extraction + save

Total LLM calls: 2 (plan + gap analysis). No hardcoded topics or websites.

Every record includes:
  - cves_mentioned, cve_pairs     → exploit_cooccurrence index
  - cwes_mentioned                → shared_cwe index
  - exploit_chains                → CVE pairs mentioned as chained
  - campaign_signals              → coordinated campaign phrases
  - owasp_categories              → shared_owasp index
  - cvss_scores_found             → contextual CVSS mentions
  - affected_products             → shared_product index
  - mitre_techniques              → ATT&CK technique IDs
  - source_type                   → for downstream filtering

Usage:
    python data/crawl_blogs.py
    python data/crawl_blogs.py --config data/sources.yaml
    python data/crawl_blogs.py --no-dynamic       # skip Vulhub + NVD refs
    python data/crawl_blogs.py --no-round2        # skip gap analysis round
    python data/crawl_blogs.py --concurrency 20
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests
import yaml
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, CacheMode

# Load .env from project root
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)
        print(f"✔  Loaded .env from {_env_path}")
    else:
        print("ℹ  No .env found — using shell environment variables")
except ImportError:
    print("ℹ  python-dotenv not installed — using shell environment variables only")

DEFAULT_CONFIG = Path(__file__).parent / "sources.yaml"

# Rate-limit retry settings for free-tier OpenRouter models
LLM_MAX_RETRIES = 3
LLM_RETRY_BASE_DELAY = 10

# Fallback order — if the primary model is rate-limited, try the next
FREE_MODEL_FALLBACKS = [
    "google/gemma-3n-e2b-it:free",
    "google/gemma-3-27b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "deepseek/deepseek-r1:free",
    "mistralai/mistral-7b-instruct:free",
]


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

def load_config(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"[ERROR] Config not found: {path}")
    with open(path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    print(f"✔  Config: {path}")
    return cfg


# ══════════════════════════════════════════════════════════════════════════════
# OPENROUTER (LLM)  +  TAVILY (search)
# ══════════════════════════════════════════════════════════════════════════════

def init_llm(cfg: dict):
    """Initialize OpenRouter client. Returns (client, model_list)."""
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("[ERROR] openai not installed. Run: pip install openai")

    settings = cfg.get("settings", {})
    api_key  = os.environ.get(settings.get("openrouter_api_key_env", "OPENROUTER_API_KEY"), "")
    primary  = settings.get("llm_model", "google/gemma-3n-e2b-it:free")

    if not api_key:
        sys.exit("[ERROR] OPENROUTER_API_KEY not set in environment")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        default_headers={
            "HTTP-Referer": "https://github.com/vuln-pipeline",
            "X-Title":      "VulnResearchCrawler",
        },
    )
    models = [primary] + [m for m in FREE_MODEL_FALLBACKS if m != primary]
    print(f"✔  OpenRouter ready: {primary}  (+ {len(models)-1} fallbacks)")
    return client, models


def init_tavily(cfg: dict):
    """Initialize Tavily search client."""
    try:
        from tavily import TavilyClient
    except ImportError:
        sys.exit("[ERROR] tavily-python not installed. Run: pip install tavily-python")

    settings = cfg.get("settings", {})
    api_key  = os.environ.get(settings.get("tavily_api_key_env", "TAVILY_API_KEY"), "")

    if not api_key:
        sys.exit("[ERROR] TAVILY_API_KEY not set in environment")

    client = TavilyClient(api_key=api_key)
    print("✔  Tavily ready")
    return client


def _llm_call_with_fallback(
    client, models: list[str], messages: list[dict],
    max_tokens: int, temperature: float,
) -> str:
    """Try each model in order with retries on 429. Returns raw response text."""
    last_err = None
    for model in models:
        for attempt in range(LLM_MAX_RETRIES):
            try:
                resp = client.chat.completions.create(
                    model=model, messages=messages,
                    max_tokens=max_tokens, temperature=temperature,
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                last_err = e
                if "429" in str(e):
                    if attempt < LLM_MAX_RETRIES - 1:
                        wait = LLM_RETRY_BASE_DELAY * (2 ** attempt)
                        print(f"    ⏳ {model.split('/')[-1]} rate-limited, retry in {wait}s ({attempt+2}/{LLM_MAX_RETRIES})")
                        time.sleep(wait)
                    else:
                        print(f"    ⚠  {model.split('/')[-1]} exhausted retries, trying next model...")
                        break
                elif "404" in str(e):
                    print(f"    ⚠  {model.split('/')[-1]} not found (404), trying next model...")
                    break
                else:
                    raise e
    raise last_err


def _parse_json_array(raw: str) -> list:
    """Robustly extract a JSON array from LLM output."""
    # Strip markdown code fences
    raw = re.sub(r"^```[a-z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)

    # Try to find a JSON array in the response
    match = re.search(r"\[.*\]", raw, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(raw)


def tavily_search(client, query: str, max_results: int = 10) -> list[dict]:
    """Run a single Tavily search. Returns list of {title, url, snippet}."""
    try:
        resp = client.search(
            query=query,
            search_depth="advanced",
            max_results=max_results,
            include_answer=False,
        )
        return [
            {
                "title":   r.get("title", ""),
                "url":     r.get("url", ""),
                "snippet": r.get("content", "")[:300],
            }
            for r in resp.get("results", [])
        ]
    except Exception as e:
        print(f"    ⚠  Tavily search failed ({query[:50]!r}): {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1: LLM PLANS SEARCH STRATEGY  (1 call)
# ══════════════════════════════════════════════════════════════════════════════

SEARCH_PLAN_PROMPT = """You are an expert cybersecurity OSINT researcher building a vulnerability dataset.

Your goal: generate search queries that find pages with VULNERABILITY CORRELATION and CO-OCCURRENCE signals — pages where multiple CVEs appear together.

Target content types:
1. EXPLOIT CHAINS — multi-CVE attack sequences (CVE-A → CVE-B), chained vulns
2. APT/RANSOMWARE CAMPAIGNS — threat groups using multiple CVEs, CISA/FBI advisories
3. CWE WEAKNESS FAMILIES — injection (CWE-89, CWE-78), memory corruption (CWE-120, CWE-416), auth bypass (CWE-287), deserialization (CWE-502) with real CVE examples
4. PRODUCT CVE CLUSTERS — Apache, Microsoft, Linux kernel, Cisco, Fortinet, Kubernetes advisories listing multiple CVEs
5. VULNERABILITY RESEARCH — Project Zero, PortSwigger, Rapid7, HackerOne deep-dives
6. RECENT HIGH-IMPACT — 2023-2025 critical vulns, actively exploited, zero-days
7. EXPLOIT DATABASES — PoC code, exploit analysis with CVE references
8. CLOUD/CONTAINER — Docker escapes, K8s privilege escalation, AWS/GCP/Azure CVEs

Generate exactly {n_queries} diverse search queries. Rules:
- Return ONLY a JSON array of strings, nothing else
- Each query should surface technical content with multiple CVEs
- Include year qualifiers (2023/2024/2025) for freshness in several queries
- Mix broad ("CISA advisory multiple CVE 2024") with specific ("Log4j exploit chain CVE-2021-44228")
- Prioritise pages likely to contain 2+ CVEs (the core co-occurrence signal)

JSON array:"""


def llm_plan_searches(client, models: list[str], n_queries: int = 25) -> list[str]:
    """Phase 1: LLM generates all search queries in one call."""
    print("\n🧠  Phase 1: LLM planning search strategy...")
    prompt = SEARCH_PLAN_PROMPT.format(n_queries=n_queries)

    try:
        raw = _llm_call_with_fallback(
            client, models,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096, temperature=0.4,
        )
        queries = _parse_json_array(raw)
        result = [q for q in queries if isinstance(q, str) and len(q) > 5][:n_queries]
        print(f"  ✔  LLM generated {len(result)} search queries")
        for i, q in enumerate(result):
            print(f"    {i+1:2d}. {q[:90]}")
        return result

    except Exception as e:
        print(f"  ⚠  LLM planning failed: {e}")
        print("  →  Using fallback query set")
        return _fallback_queries()


def _fallback_queries() -> list[str]:
    """Backup if LLM planning fails entirely."""
    return [
        "CVE exploit chain multiple vulnerabilities chained 2024",
        "APT campaign multiple CVE CISA advisory 2024",
        "ransomware group CVE list exploit vulnerabilities 2024",
        "CISA known exploited vulnerabilities advisory multiple CVE",
        "Microsoft Patch Tuesday multiple CVE critical 2024",
        "Apache Log4j Struts multiple CVE exploit chain",
        "Linux kernel privilege escalation CVE chain 2024",
        "SQL injection CWE-89 CVE examples exploit analysis",
        "buffer overflow use-after-free CVE exploit chain",
        "authentication bypass CWE-287 CVE writeup",
        "insecure deserialization CWE-502 RCE CVE",
        "Cisco Fortinet Palo Alto CVE advisory multiple vulnerabilities",
        "Kubernetes Docker container escape CVE chain",
        "Google Project Zero vulnerability research CVE",
        "PortSwigger web security research CVE CWE",
        "Rapid7 vulnerability analysis CVE affected products",
        "HackerOne disclosed vulnerability chain multiple CVE",
        "zero-day actively exploited CVE 2024 2025",
        "SSRF CSRF XSS CVE exploit chain web vulnerability",
        "cloud security AWS Azure GCP CVE advisory 2024",
        "exploit-db proof of concept CVE vulnerability analysis",
        "Qualys Tenable vulnerability report multiple CVE",
        "threat intelligence CVE correlation co-occurrence analysis",
        "MITRE ATT&CK technique CVE mapping vulnerability",
        "vulnerability advisory multiple CVE patch 2025",
    ]


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2: TAVILY DISCOVERS URLs  (parallel searches)
# ══════════════════════════════════════════════════════════════════════════════

def discover_urls_via_tavily(
    tavily_client, queries: list[str],
    max_results_per_query: int = 10,
) -> dict[str, str]:
    """Phase 2: Run all Tavily queries, collect unique URLs with source_type."""
    print(f"\n🔎  Phase 2: Tavily discovering URLs ({len(queries)} queries)...")
    url_map: dict[str, str] = {}
    total_results = 0

    for i, query in enumerate(queries):
        print(f"  [{i+1}/{len(queries)}] {query[:80]}")
        results = tavily_search(tavily_client, query, max_results=max_results_per_query)
        total_results += len(results)

        for r in results:
            url = r.get("url", "")
            if url and url not in url_map:
                url_map[url] = _infer_source_type(url)

        time.sleep(0.3)  # stay polite with Tavily

    print(f"  ✔  {total_results} results → {len(url_map)} unique URLs")
    return url_map


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3: DYNAMIC SOURCES  (Vulhub + NVD refs — no API keys needed)
# ══════════════════════════════════════════════════════════════════════════════

def discover_vulhub_readmes(dyn_cfg: dict) -> list[str]:
    api_url  = dyn_cfg["api_url"]
    raw_base = dyn_cfg["raw_base"]
    limit    = dyn_cfg.get("max_readmes", 100)
    print("  Vulhub: querying GitHub Tree API...")
    try:
        resp = requests.get(
            api_url, timeout=20,
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        tree  = resp.json().get("tree", [])
        paths = [
            i["path"] for i in tree
            if i["path"].endswith("README.md")
            and re.search(r"CVE-\d{4}-\d+", i["path"])
        ]
        urls = [f"{raw_base}{p}" for p in paths[:limit]]
        print(f"  ✔  {len(urls)} Vulhub CVE READMEs")
        return urls
    except Exception as e:
        print(f"  ⚠  Vulhub failed: {e}")
        return []


def harvest_nvd_reference_urls(dyn_cfg: dict) -> list[str]:
    nvd_path  = Path(dyn_cfg.get("nvd_data_path", "data/raw_nvd.json"))
    max_total = dyn_cfg.get("max_urls", 150)
    top_n     = dyn_cfg.get("top_cvss_count", 500)
    allowed   = dyn_cfg.get("allowed_domains", [])

    if not nvd_path.exists():
        print(f"  ⚠  NVD file not found ({nvd_path}), skipping ref harvest")
        return []

    with open(nvd_path, encoding="utf-8") as f:
        records = json.load(f)

    prioritised = sorted(
        [r for r in records if r.get("cvss_score")],
        key=lambda r: float(r.get("cvss_score") or 0),
        reverse=True,
    )[:top_n]

    urls, seen = [], set()
    for rec in prioritised:
        for ref in rec.get("references", []):
            url = ref if isinstance(ref, str) else ref.get("url", "")
            if not url or url in seen:
                continue
            if any(d in url for d in allowed):
                urls.append(url)
                seen.add(url)
        if len(urls) >= max_total:
            break

    print(f"  ✔  {len(urls)} NVD reference URLs")
    return urls


def discover_dynamic_sources(cfg: dict) -> dict[str, str]:
    """Phase 3: Collect URLs from dynamic API sources."""
    dyn = cfg.get("dynamic", {})
    url_map: dict[str, str] = {}

    print("\n📂  Phase 3: Dynamic source discovery...")

    vulhub_cfg = dyn.get("vulhub", {})
    if vulhub_cfg.get("enabled", True):
        for url in discover_vulhub_readmes(vulhub_cfg):
            url_map[url] = "vulhub_writeup"

    nvd_cfg = dyn.get("nvd_references", {})
    if nvd_cfg.get("enabled", True):
        for url in harvest_nvd_reference_urls(nvd_cfg):
            if url not in url_map:
                url_map[url] = _infer_source_type(url)

    print(f"  ✔  {len(url_map)} dynamic URLs total")
    return url_map


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED EXTRACTION  (regex-based, no LLM needed)
# ══════════════════════════════════════════════════════════════════════════════

def extract_correlation_signals(markdown: str, cfg: dict) -> dict:
    """
    Extract ALL structured signals for the correlation/co-occurrence pipeline.
    Any page mentioning 2+ CVEs is a co-occurrence signal.
    """
    ext = cfg.get("extraction_targets", {})

    # ── CVEs ──────────────────────────────────────────────────────────────
    cves = list(set(re.findall(r"CVE-\d{4}-\d+", markdown, re.I)))
    cves = [c.upper() for c in cves]

    # ── All CVE pairs on same page = implicit co-occurrence ───────────────
    cve_pairs: list[dict] = []
    if len(cves) >= 2:
        seen_pairs: set = set()
        for i, ca in enumerate(cves):
            for cb in cves[i+1:]:
                pair = tuple(sorted([ca, cb]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    cve_pairs.append({"cve_a": pair[0], "cve_b": pair[1], "signal": "co_page"})

    # ── CWEs ──────────────────────────────────────────────────────────────
    cwes = list(set(re.findall(r"CWE-\d+", markdown, re.I)))
    cwes = [c.upper() for c in cwes]

    # ── OWASP categories ──────────────────────────────────────────────────
    owasp = list(set(re.findall(r"A\d{2}:20\d\d", markdown)))

    # ── CVSS scores ───────────────────────────────────────────────────────
    cvss_hits = re.findall(r"CVSS[v23\s:]+[\d.]+", markdown, re.I)

    # ── MITRE ATT&CK technique IDs ────────────────────────────────────────
    mitre_techs = list(set(re.findall(r"T\d{4}(?:\.\d{3})?", markdown)))

    # ── Affected products ─────────────────────────────────────────────────
    product_patterns = [
        r"(?:affects?|vulnerable|patched in|fixed in)\s+([\w\s\-\.]{3,40}?)\s+(?:v?[\d]+\.[\d]+|version)",
        r"([\w\-\.]{3,30})\s+(?:v?[\d]+\.[\d]+\.[\d]+)",
    ]
    products: list[str] = []
    for pat in product_patterns:
        products.extend(re.findall(pat, markdown, re.I))
    products = list(set(p.strip().lower() for p in products if 2 < len(p.strip()) < 40))[:30]

    # ── Exploit chains — CVE pairs with explicit chaining context ─────────
    chain_phrases = ext.get("exploit_chain_phrases", [
        "chain", "chained", "combined", "initial access", "privilege escalation",
        "lateral movement", "followed by", "then", "leads to", "allows",
        "escalate", "pivot", "bypass", "then exploit",
    ])
    chains: list[dict] = []
    sentences = re.split(r"[.\n]", markdown)
    seen_chain_pairs: set = set()
    for sent in sentences:
        found = re.findall(r"CVE-\d{4}-\d+", sent, re.I)
        if len(found) >= 2:
            has_chain_phrase = any(p.lower() in sent.lower() for p in chain_phrases)
            if has_chain_phrase:
                pair = tuple(sorted([found[0].upper(), found[1].upper()]))
                if pair not in seen_chain_pairs:
                    seen_chain_pairs.add(pair)
                    chains.append({
                        "cve_a":   pair[0],
                        "cve_b":   pair[1],
                        "signal":  "explicit_chain",
                        "context": sent.strip()[:300],
                    })

    # Same-paragraph co-occurrence as weaker chain signal
    paragraphs = markdown.split("\n\n")
    for para in paragraphs:
        found = list(set(re.findall(r"CVE-\d{4}-\d+", para, re.I)))
        if len(found) >= 2:
            for i, ca in enumerate(found):
                for cb in found[i+1:]:
                    pair = tuple(sorted([ca.upper(), cb.upper()]))
                    if pair not in seen_chain_pairs:
                        seen_chain_pairs.add(pair)
                        chains.append({
                            "cve_a":  pair[0],
                            "cve_b":  pair[1],
                            "signal": "same_paragraph",
                            "context": para.strip()[:200],
                        })

    # ── Campaign signals — CVEs + threat actor context ────────────────────
    campaign_phrases = ext.get("campaign_phrases", [
        "ransomware", "threat actor", "APT", "nation-state", "attributed",
        "exploited in the wild", "actively exploited", "campaign", "group",
        "espionage", "targeted attack", "zero-day", "0-day", "in the wild",
    ])
    campaign_hits: list[str] = []
    for sent in sentences:
        if re.search(r"CVE-\d{4}-\d+", sent, re.I):
            if any(p.lower() in sent.lower() for p in campaign_phrases):
                campaign_hits.append(sent.strip()[:300])

    # ── Severity context ──────────────────────────────────────────────────
    severity_mentions = re.findall(
        r"(?:critical|high|medium|low)\s+(?:severity|risk|vulnerability|CVE)",
        markdown, re.I,
    )

    return {
        "cves_mentioned":    cves,
        "cve_pairs":         cve_pairs[:100],
        "cwes_mentioned":    cwes,
        "owasp_categories":  owasp,
        "cvss_scores_found": cvss_hits[:10],
        "mitre_techniques":  mitre_techs[:20],
        "affected_products": products,
        "exploit_chains":    chains[:50],
        "campaign_signals":  campaign_hits[:10],
        "severity_context":  severity_mentions[:10],
    }


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 + 5: CONCURRENT CRAWL  +  LINK HARVESTING
# ══════════════════════════════════════════════════════════════════════════════

def harvest_links_from_markdown(markdown: str) -> list[str]:
    """
    Phase 5: Extract URLs from crawled page content that look like they
    lead to more CVE-rich pages. The agent "follows" promising links.
    """
    url_pattern = r'https?://[^\s\)\]\>"\'`]+'
    found_urls = re.findall(url_pattern, markdown)

    security_domains = [
        "cve.org", "nvd.nist.gov", "cisa.gov", "exploit-db.com",
        "github.com/advisories", "security.googleblog", "portswigger.net",
        "rapid7.com", "qualys.com", "tenable.com", "snyk.io",
        "msrc.microsoft.com", "hackerone.com", "zerodayinitiative",
        "securitylab.github", "blog.", "research.", "advisory",
    ]

    harvested = []
    seen = set()
    for url in found_urls:
        url = url.rstrip(".,;:)")
        if url in seen:
            continue
        seen.add(url)
        if re.search(r"CVE-\d{4}-\d+", url, re.I):
            harvested.append(url)
        elif any(d in url.lower() for d in security_domains):
            harvested.append(url)

    return harvested[:50]


def is_quality_content(text: str, keywords: list[str], min_chars: int) -> bool:
    stripped = text.strip()
    if re.search(r"CVE-\d{4}-\d+", stripped, re.I):
        return len(stripped) >= 50
    if len(stripped) < min_chars:
        return False
    lower = stripped.lower()
    return any(kw in lower for kw in keywords)


def make_record(url: str, markdown: str, source_type: str, cfg: dict) -> dict:
    settings  = cfg.get("settings", {})
    max_chars = settings.get("max_content_chars", 10000)
    signals   = extract_correlation_signals(markdown, cfg)
    return {
        "url":         url,
        "source_type": source_type,
        "content":     markdown[:max_chars],
        **signals,
    }


async def crawl_url(
    crawler: AsyncWebCrawler, url: str, source_type: str,
    semaphore: asyncio.Semaphore, cfg: dict, idx: int, total: int,
) -> tuple[Optional[dict], list[str]]:
    """Crawl a single URL. Returns (record_or_None, harvested_links)."""
    settings  = cfg.get("settings", {})
    keywords  = cfg.get("quality_keywords", [])
    min_chars = settings.get("min_content_chars", 300)

    async with semaphore:
        try:
            run_cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS)
            result  = await crawler.arun(url=url, config=run_cfg)

            if result.success and result.markdown:
                harvested = harvest_links_from_markdown(result.markdown)

                if is_quality_content(result.markdown, keywords, min_chars):
                    record   = make_record(url, result.markdown, source_type, cfg)
                    n_cves   = len(record["cves_mentioned"])
                    n_chains = len(record["exploit_chains"])
                    tags = []
                    if n_cves:   tags.append(f"{n_cves} CVEs")
                    if n_chains: tags.append(f"{n_chains} chains")
                    tag_str = f" [{', '.join(tags)}]" if tags else ""
                    print(f"  ✅ [{idx}/{total}] {source_type:<25} {url[:55]}{tag_str}")
                    return record, harvested
                else:
                    print(f"  ⚠  [{idx}/{total}] Low quality: {url[:60]}")
                    return None, harvested
            else:
                print(f"  ❌ [{idx}/{total}] Failed: {url[:60]}")
        except Exception as e:
            print(f"  ❌ [{idx}/{total}] Error ({url[:45]}): {e}")

    return None, []


async def crawl_all_concurrent(
    url_map: dict[str, str], cfg: dict, concurrency: int,
) -> tuple[list[dict], list[str]]:
    """Crawl all URLs concurrently. Returns (records, all_harvested_links)."""
    urls      = list(url_map.keys())
    total     = len(urls)
    semaphore = asyncio.Semaphore(concurrency)

    print(f"\n🌐  Crawling {total} URLs  [{concurrency} concurrent workers]\n")

    async with AsyncWebCrawler(verbose=False) as crawler:
        tasks = [
            crawl_url(crawler, url, url_map[url], semaphore, cfg, i+1, total)
            for i, url in enumerate(urls)
        ]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    records = []
    all_harvested: list[str] = []

    for r in raw_results:
        if isinstance(r, tuple):
            record, harvested = r
            if record:
                records.append(record)
            all_harvested.extend(harvested)

    # ── Summary ──────────────────────────────────────────────────────────────
    failed       = total - len(records)
    total_cves   = sum(len(r.get("cves_mentioned", [])) for r in records)
    total_pairs  = sum(len(r.get("cve_pairs", [])) for r in records)
    total_chains = sum(len(r.get("exploit_chains", [])) for r in records)
    total_camp   = sum(len(r.get("campaign_signals", [])) for r in records)
    total_cwes   = sum(len(r.get("cwes_mentioned", [])) for r in records)

    print(f"\n  ✔  {len(records)} pages kept  |  {failed} failed/filtered")
    print(f"  📊 CVE mentions: {total_cves}  |  CVE pairs: {total_pairs}")
    print(f"  📊 Exploit chains: {total_chains}  |  Campaign signals: {total_camp}  |  CWE mentions: {total_cwes}")
    print(f"  🔗 {len(all_harvested)} links harvested from crawled pages")

    return records, all_harvested


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6: LLM GAP ANALYSIS  (1 call)
# ══════════════════════════════════════════════════════════════════════════════

def llm_gap_analysis(
    client, models: list[str],
    records: list[dict], n_queries: int = 10,
) -> list[str]:
    """Phase 6: LLM reviews Round 1 results and generates follow-up queries."""
    print("\n🧠  Phase 6: LLM gap analysis...")

    total_cves   = sum(len(r.get("cves_mentioned", [])) for r in records)
    total_pairs  = sum(len(r.get("cve_pairs", [])) for r in records)
    total_chains = sum(len(r.get("exploit_chains", [])) for r in records)
    total_cwes   = sum(len(r.get("cwes_mentioned", [])) for r in records)
    total_camp   = sum(len(r.get("campaign_signals", [])) for r in records)
    total_prods  = sum(len(r.get("affected_products", [])) for r in records)

    all_cwes = set()
    all_prods = set()
    for r in records:
        all_cwes.update(r.get("cwes_mentioned", []))
        all_prods.update(r.get("affected_products", []))

    source_types = {}
    for r in records:
        st = r.get("source_type", "unknown")
        source_types[st] = source_types.get(st, 0) + 1

    prompt = f"""You are analysing vulnerability intelligence crawl results to find GAPS.

Round 1 collected:
- {len(records)} pages, {total_cves} CVE mentions, {total_pairs} CVE co-occurrence pairs
- {total_chains} exploit chain signals, {total_camp} campaign signals
- {total_cwes} CWE mentions: {', '.join(sorted(all_cwes)[:20])}
- {total_prods} product mentions: {', '.join(sorted(all_prods)[:20])}
- Source types: {json.dumps(source_types)}

Generate {n_queries} follow-up search queries to fill gaps:
- Major CWE families missing? (e.g., XSS/CWE-79, SSRF/CWE-918, path traversal/CWE-22)
- Major products missing? (e.g., Cisco, Fortinet, VMware, Oracle, SAP)
- Not enough exploit chains? Search for more chained vulnerability writeups
- Not enough campaign data? Search for more APT/ransomware reports with CVE lists
- Recent 2024-2025 CVEs underrepresented?

Return ONLY a JSON array of {n_queries} query strings:"""

    try:
        raw = _llm_call_with_fallback(
            client, models,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048, temperature=0.3,
        )
        queries = _parse_json_array(raw)
        result = [q for q in queries if isinstance(q, str) and len(q) > 5][:n_queries]
        print(f"  ✔  LLM generated {len(result)} follow-up queries")
        for i, q in enumerate(result):
            print(f"    {i+1:2d}. {q[:90]}")
        return result

    except Exception as e:
        print(f"  ⚠  Gap analysis failed: {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _infer_source_type(url: str) -> str:
    """Heuristic source_type from URL domain."""
    u = url.lower()
    if "exploit-db.com" in u:               return "exploit_writeup"
    if "owasp.org" in u:                    return "owasp_guide"
    if "vulhub" in u:                       return "vulhub_writeup"
    if "portswigger" in u:                  return "portswigger_research"
    if "rapid7.com" in u:                   return "rapid7_blog"
    if "googleprojectzero" in u:            return "project_zero"
    if "snyk.io" in u or "wiz.io" in u:     return "cloud_security_research"
    if "cisa.gov" in u:                     return "cisa_advisory"
    if "msrc.microsoft.com" in u:           return "msrc_advisory"
    if "github.com" in u:                   return "github_advisory"
    if "hackerone.com" in u:                return "hackerone_disclosed"
    if "zerodayinitiative" in u:            return "zdi_advisory"
    if "qualys" in u:                       return "qualys_research"
    if "tenable" in u:                      return "tenable_research"
    if "nvd.nist.gov" in u:                 return "nvd_reference"
    if "cve.org" in u:                      return "cve_record"
    return "research_blog"


def print_report(data: list[dict], out_file: str):
    """Final summary report."""
    source_counts: dict[str, int] = {}
    for d in data:
        st = d.get("source_type", "unknown")
        source_counts[st] = source_counts.get(st, 0) + 1

    total_pairs  = sum(len(d.get("cve_pairs", [])) for d in data)
    total_chains = sum(len(d.get("exploit_chains", [])) for d in data)
    total_camp   = sum(len(d.get("campaign_signals", [])) for d in data)
    cve_pages    = sum(1 for d in data if d.get("cves_mentioned"))
    chain_pages  = sum(1 for d in data if d.get("exploit_chains"))
    camp_pages   = sum(1 for d in data if d.get("campaign_signals"))
    cwe_pages    = sum(1 for d in data if d.get("cwes_mentioned"))

    print(f"\n{'='*65}")
    print(f"✅  Saved {len(data)} records → {out_file}")
    print(f"{'='*65}")
    print(f"\n   Co-occurrence signal summary:")
    print(f"     Pages with CVE mentions:      {cve_pages}")
    print(f"     Total CVE pairs:              {total_pairs}  (direct co-occurrence signals)")
    print(f"     Pages with exploit chains:    {chain_pages}  ({total_chains} chain pairs)")
    print(f"     Pages with campaign signals:  {camp_pages}  ({total_camp} sentences)")
    print(f"     Pages with CWE mentions:      {cwe_pages}")
    print(f"\n   By source type:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"     {src:<30} {cnt}")


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def run(
    config_path: Path,
    out_override: str | None = None,
    use_dynamic: bool = True,
    use_round2:  bool = True,
    concurrency: int | None = None,
):
    cfg      = load_config(config_path)
    settings = cfg.get("settings", {})
    out_file = out_override or settings.get("output_file", "data/raw_blogs.json")
    workers  = concurrency or settings.get("concurrent_tasks", 15)
    max_total = settings.get("max_total_urls", 600)
    n_queries = settings.get("n_search_queries", 25)

    # ── Phase 1: LLM plans search strategy (1 LLM call) ─────────────────
    llm_client, llm_models = init_llm(cfg)
    tavily_client = init_tavily(cfg)
    queries = llm_plan_searches(llm_client, llm_models, n_queries=n_queries)

    # ── Phase 2: Tavily discovers URLs ───────────────────────────────────
    url_map = discover_urls_via_tavily(
        tavily_client, queries,
        max_results_per_query=settings.get("max_results_per_query", 10),
    )

    # ── Phase 3: Dynamic sources (Vulhub + NVD refs) ─────────────────────
    if use_dynamic:
        dynamic_urls = discover_dynamic_sources(cfg)
        for url, src_type in dynamic_urls.items():
            if url not in url_map:
                url_map[url] = src_type
    else:
        print("\n  --no-dynamic: skipping Vulhub + NVD refs")

    # Cap Round 1
    if len(url_map) > max_total:
        print(f"  Capping at {max_total} URLs (had {len(url_map)})")
        url_map = dict(list(url_map.items())[:max_total])

    print(f"\n  Total unique URLs for Round 1: {len(url_map)}")

    # ── Phase 4+5: Crawl + link harvest ──────────────────────────────────
    records, harvested_links = asyncio.run(
        crawl_all_concurrent(url_map, cfg, workers)
    )

    # ── Phase 5b: Crawl harvested links (new URLs from content) ──────────
    already_crawled = set(url_map.keys())
    new_links = [u for u in set(harvested_links) if u not in already_crawled]
    max_harvest = settings.get("max_harvested_urls", 100)
    harvest_map: dict[str, str] = {}

    if new_links:
        new_links = new_links[:max_harvest]
        harvest_map = {u: _infer_source_type(u) for u in new_links}
        print(f"\n🔗  Phase 5b: Crawling {len(harvest_map)} harvested links...")

        harvest_records, _ = asyncio.run(
            crawl_all_concurrent(harvest_map, cfg, workers)
        )
        records.extend(harvest_records)

    # ── Phase 6+7: LLM gap analysis → Round 2 ───────────────────────────
    if use_round2 and records:
        r2_queries = llm_gap_analysis(
            llm_client, llm_models, records,
            n_queries=settings.get("n_round2_queries", 10),
        )

        if r2_queries:
            print(f"\n🔄  Round 2: Discovering + crawling for gap-fill...")
            r2_url_map = discover_urls_via_tavily(
                tavily_client, r2_queries,
                max_results_per_query=settings.get("max_results_per_query", 10),
            )

            # Remove already-crawled URLs
            all_crawled = already_crawled | set(harvest_map.keys())
            r2_url_map = {u: st for u, st in r2_url_map.items() if u not in all_crawled}

            if r2_url_map:
                max_r2 = settings.get("max_round2_urls", 150)
                if len(r2_url_map) > max_r2:
                    r2_url_map = dict(list(r2_url_map.items())[:max_r2])

                r2_records, _ = asyncio.run(
                    crawl_all_concurrent(r2_url_map, cfg, workers)
                )
                records.extend(r2_records)
                print(f"  ✔  Round 2 added {len(r2_records)} records")
    elif not use_round2:
        print("\n  --no-round2: skipping gap analysis")

    # ── Phase 8: Save + report ───────────────────────────────────────────
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    print_report(records, out_file)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fully agentic vulnerability intelligence crawler"
    )
    parser.add_argument("--config",      default=str(DEFAULT_CONFIG))
    parser.add_argument("--out",         default=None, help="Override output path")
    parser.add_argument("--no-dynamic",  action="store_true",
                        help="Skip Vulhub + NVD dynamic sources")
    parser.add_argument("--no-round2",   action="store_true",
                        help="Skip LLM gap analysis round")
    parser.add_argument("--concurrency", type=int, default=None,
                        help="Override concurrent workers")
    args = parser.parse_args()

    run(
        config_path  = Path(args.config),
        out_override = args.out,
        use_dynamic  = not args.no_dynamic,
        use_round2   = not args.no_round2,
        concurrency  = args.concurrency,
    )
