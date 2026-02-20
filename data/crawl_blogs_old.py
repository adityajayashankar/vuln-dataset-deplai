"""
crawl_blogs.py  —  Agentic concurrent security blog crawler
------------------------------------------------------------
Outputs raw_blogs.json structured for the correlation/co-occurrence pipeline.

Every record includes:
  - cves_mentioned      → feeds exploit_cooccurrence index
  - cwes_mentioned      → feeds shared_cwe index  
  - exploit_chains      → pairs of CVEs mentioned as chained
  - campaign_signals    → phrases indicating coordinated campaigns
  - owasp_categories    → feeds shared_owasp index
  - cvss_scores_found   → contextual CVSS mentions
  - affected_products   → feeds shared_product index
  - source_type         → for downstream filtering

Flow:
  1. Load sources.yaml
  2. Agent: Google Custom Search per topic → LLM picks best URLs
  3. Dynamic: Vulhub GitHub API + NVD reference harvesting
  4. Concurrent crawl with crawl4ai (semaphore-controlled)
  5. Structured extraction pass on each page
  6. Save to raw_blogs.json

Usage:
    python data/crawl_blogs.py
    python data/crawl_blogs.py --config data/sources.yaml
    python data/crawl_blogs.py --no-agent        # skip Google search, only dynamic sources
    python data/crawl_blogs.py --no-vulhub --no-nvd-refs
    python data/crawl_blogs.py --concurrency 20  # override concurrent workers
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

import requests
import yaml
from crawl4ai import AsyncWebCrawler, CrawlerRunConfig, CacheMode

# Load .env from project root (works whether run standalone or via run_pipeline.py)
try:
    from dotenv import load_dotenv
    _env_path = Path(__file__).parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path, override=False)  # override=False: shell env wins
        print(f"✔  Loaded .env from {_env_path}")
    else:
        print("ℹ  No .env found — using shell environment variables")
except ImportError:
    print("ℹ  python-dotenv not installed — using shell environment variables only")
    print("   To auto-load .env: pip install python-dotenv")

DEFAULT_CONFIG = Path(__file__).parent / "sources.yaml"

# Rate-limit retry settings for free-tier OpenRouter models
LLM_MAX_RETRIES = 3
LLM_RETRY_BASE_DELAY = 10   # seconds between retries for same model

# Fallback order — if the primary model is rate-limited upstream, try the next
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
    """
    Initialize OpenRouter client.
    Returns (client, model_list) where model_list is the primary model
    followed by free fallbacks for automatic rotation on 429.
    """
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("[ERROR] openai not installed. Run: pip install openai")

    settings   = cfg.get("settings", {})
    api_key    = os.environ.get(settings.get("openrouter_api_key_env", "OPENROUTER_API_KEY"), "")
    primary    = settings.get("llm_model", "google/gemma-3n-e2b-it:free")

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

    # Build ordered model list: primary first, then fallbacks (deduped)
    models = [primary] + [m for m in FREE_MODEL_FALLBACKS if m != primary]
    print(f"✔  OpenRouter ready: {primary}  (+ {len(models)-1} fallbacks)")
    return client, models



def init_tavily(cfg: dict):
    """
    Initialize Tavily search client from TAVILY_API_KEY env var.
    pip install tavily-python
    Free tier: 1000 searches/month — https://tavily.com
    """
    try:
        from tavily import TavilyClient
    except ImportError:
        sys.exit("[ERROR] tavily-python not installed. Run: pip install tavily-python")

    settings = cfg.get("settings", {})
    api_key  = os.environ.get(settings.get("tavily_api_key_env", "TAVILY_API_KEY"), "")

    if not api_key:
        sys.exit("[ERROR] TAVILY_API_KEY not set in environment")

    client = TavilyClient(api_key=api_key)
    print(f"✔  Tavily ready")
    return client


def tavily_search(
    client,
    query: str,
    max_results: int = 10,
) -> list[dict]:
    """
    Tavily search — purpose-built for AI agents.
    Returns list of {title, link, snippet} matching the google_search
    output shape so the rest of the pipeline is unchanged.
    Free tier: 1000 searches/month.
    """
    try:
        resp = client.search(
            query=query,
            search_depth="advanced",   # deeper crawl, better snippets
            max_results=max_results,
            include_answer=False,      # raw results only, no summarisation
        )
        # Normalise to {title, link, snippet}
        return [
            {
                "title":   r.get("title", ""),
                "link":    r.get("url", ""),
                "snippet": r.get("content", "")[:300],
            }
            for r in resp.get("results", [])
        ]
    except Exception as e:
        print(f"    ⚠  Tavily search failed ({query[:50]!r}): {e}")
        return []


def _llm_call_with_fallback(
    client,
    models: list[str],
    messages: list[dict],
    max_tokens: int,
    temperature: float,
) -> str:
    """
    Try each model in order. Per model: retry LLM_MAX_RETRIES times on 429.
    If all retries for a model fail, move to the next model.
    Returns the raw response text, or raises the last exception.
    """
    last_err = None
    for model in models:
        for attempt in range(LLM_MAX_RETRIES):
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                return resp.choices[0].message.content.strip()
            except Exception as e:
                last_err = e
                if "429" in str(e):
                    if attempt < LLM_MAX_RETRIES - 1:
                        wait = LLM_RETRY_BASE_DELAY * (2 ** attempt)
                        print(f"    \u23f3 {model.split('/')[-1]} rate-limited, retry in {wait}s ({attempt+2}/{LLM_MAX_RETRIES})")
                        time.sleep(wait)
                    else:
                        print(f"    \u26a0  {model.split('/')[-1]} exhausted retries, trying next model...")
                        break          # move to next model
                elif "404" in str(e):
                    print(f"    \u26a0  {model.split('/')[-1]} not found (404), trying next model...")
                    break              # skip this model entirely
                else:
                    raise e            # non-rate-limit error, propagate immediately
    raise last_err  # all models exhausted


def llm_select_urls(
    client,
    models: list[str],
    results: list[dict],
    topic_name: str,
    topic_desc: str,
    max_urls: int,
) -> list[str]:
    """
    LLM reads Tavily result snippets and picks the best URLs to crawl.
    A rule can't distinguish a CVE writeup from a marketing page on the
    same domain — the LLM understands research intent from the snippet.
    Falls back to top-N links if the call fails.
    """
    if not results:
        return []

    snippets = "\n".join(
        f"[{i+1}] {r.get('title', '')} | {r.get('link', '')}\n    {r.get('snippet', '')[:200]}"
        for i, r in enumerate(results)
    )

    prompt = f"""You are a cybersecurity data pipeline assistant.

Topic: {topic_name}
Goal: {topic_desc}

Select the {max_urls} URLs most likely to contain:
- CVE technical writeups or exploit analysis
- Exploit chain descriptions (CVE-A chained with CVE-B)
- Campaign/threat actor attribution with CVE IDs
- CWE family examples with real CVE instances
- Affected product/version details tied to CVEs

Rules:
- Return ONLY a valid JSON array of URL strings. Nothing else.
- Prefer specific articles over homepages or category pages
- Skip login walls, paywalls, vendor marketing, non-technical content
- Spread across domains — no more than 2 URLs from the same domain

Search results:
{snippets}

JSON array only:"""

    try:
        raw = _llm_call_with_fallback(
            client, models,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=2048, temperature=0.1,
        )
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        urls = json.loads(raw)
        return [u for u in urls if isinstance(u, str) and u.startswith("http")][:max_urls]
    except Exception as e:
        print(f"    ⚠  LLM URL selection failed: {e} — using top Tavily results")
        return [r["link"] for r in results if r.get("link")][:max_urls]



def llm_generate_queries(client, models: list[str], topic_name: str, topic_desc: str, n: int = 4) -> list[str]:
    """
    LLM generates Tavily search queries from a plain-English description.
    search_queries in sources.yaml are optional — LLM handles it if absent.
    """
    prompt = f"""You are a cybersecurity OSINT specialist building a vulnerability dataset.

Topic: {topic_name}
Description: {topic_desc}

Generate {n} precise search queries to find high-quality technical security content.
Focus on: CVE writeups, exploit chains, PoC code, campaign analysis, CWE examples.

Rules:
- Return ONLY a JSON array of query strings, nothing else
- Be specific — queries that surface technical research, not marketing pages
- Include year 2023 or 2024 in at least one query for freshness

JSON array only:"""

    try:
        raw = _llm_call_with_fallback(
            client, models,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=256, temperature=0.3,
        )
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        queries = json.loads(raw)
        return [q for q in queries if isinstance(q, str)][:n]
    except Exception as e:
        print(f"    ⚠  LLM query generation failed: {e}")
        return [f"{topic_desc[:80]} CVE vulnerability 2024"]



def agent_discover_urls(cfg: dict, llm_client, llm_models: list[str], tavily_client) -> dict[str, list[str]]:
    """
    Full agentic loop per topic:
      1. LLM generates search queries from the topic description
      2. Tavily runs those queries
      3. LLM reads the results and selects the best URLs to crawl
    Models auto-rotate on 429: tries each free model in order.
    """
    settings = cfg.get("settings", {})
    max_urls = settings.get("max_urls_per_topic", 10)
    topics   = cfg.get("topics", [])

    discovered: dict[str, list[str]] = {}
    print(f"\n🤖  Agent discovery: {len(topics)} topics  [LLM → Tavily → LLM]  ({len(llm_models)} models available)")

    for topic in topics:
        name    = topic["name"]
        desc    = topic.get("description", name)
        queries = topic.get("search_queries")   # optional in YAML
        print(f"\n  [{name}]")

        if queries:
            print(f"    Using {len(queries)} queries from sources.yaml")
        else:
            print(f"    LLM generating search queries...")
            queries = llm_generate_queries(llm_client, llm_models, name, desc, n=4)
            print(f"    Generated {len(queries)} queries")
            time.sleep(8)   # pace LLM calls to stay under 8 req/min

        all_results: list[dict] = []
        for q in queries:
            print(f"    🔎 {q[:90]}")
            results = tavily_search(tavily_client, q, max_results=10)
            all_results.extend(results)
            time.sleep(0.3)   # Tavily is more lenient but stay polite

        print(f"    🤖 LLM selecting best {max_urls} from {len(all_results)} results...")
        urls = llm_select_urls(llm_client, llm_models, all_results, name, desc, max_urls)
        print(f"    ✔  {len(urls)} URLs selected")
        discovered[name] = urls
        time.sleep(8)   # pace LLM calls to stay under 8 req/min

    return discovered


# ══════════════════════════════════════════════════════════════════════════════
# DYNAMIC SOURCES  (Vulhub + NVD refs — no search API needed)
# ══════════════════════════════════════════════════════════════════════════════

def discover_vulhub_readmes(dyn_cfg: dict) -> list[str]:
    api_url  = dyn_cfg["api_url"]
    raw_base = dyn_cfg["raw_base"]
    limit    = dyn_cfg.get("max_readmes", 100)
    print("\n  Vulhub: querying GitHub Tree API...")
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


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURED EXTRACTION  (cybersecurity correlation signals)
# ══════════════════════════════════════════════════════════════════════════════

def extract_correlation_signals(markdown: str, cfg: dict) -> dict:
    """
    Extract ALL structured signals for the correlation/co-occurrence pipeline.

    Key insight: ANY page mentioning 2+ CVEs is a co-occurrence signal.
    We don't need fancy phrase matching — just mine everything.

    Signals:
      cves_mentioned       → primary co-occurrence input (2+ CVEs = signal)
      cve_pairs            → all unique pairs of CVEs on same page
      cwes_mentioned       → shared_cwe index
      owasp_categories     → shared_owasp index
      cvss_scores_found    → severity context
      affected_products    → shared_product index
      exploit_chains       → CVE pairs with explicit chain context
      campaign_signals     → CVEs mentioned alongside threat actor/campaign phrases
      mitre_techniques     → T#### ATT&CK technique IDs
      severity_context     → critical/high/medium mentions near CVEs
    """
    ext = cfg.get("extraction_targets", {})

    # ── CVEs — the most important signal ─────────────────────────────────
    cves = list(set(re.findall(r"CVE-\d{4}-\d+", markdown, re.I)))
    cves = [c.upper() for c in cves]

    # ── All CVE pairs on same page = implicit co-occurrence ──────────────
    cve_pairs: list[dict] = []
    if len(cves) >= 2:
        seen_pairs: set = set()
        for i, ca in enumerate(cves):
            for cb in cves[i+1:]:
                pair = tuple(sorted([ca, cb]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    cve_pairs.append({"cve_a": pair[0], "cve_b": pair[1], "signal": "co_page"})

    # ── CWEs ─────────────────────────────────────────────────────────────
    cwes = list(set(re.findall(r"CWE-\d+", markdown, re.I)))
    cwes = [c.upper() for c in cwes]

    # ── OWASP categories ─────────────────────────────────────────────────
    owasp = list(set(re.findall(r"A\d{2}:20\d\d", markdown)))

    # ── CVSS scores ───────────────────────────────────────────────────────
    cvss_hits = re.findall(r"CVSS[v23\s:]+[\d.]+", markdown, re.I)

    # ── MITRE ATT&CK technique IDs ────────────────────────────────────────
    mitre_techs = list(set(re.findall(r"T\d{4}(?:\.\d{3})?", markdown)))

    # ── Affected products ─────────────────────────────────────────────────
    product_patterns = [
        r"(?:affects?|vulnerable|patched in|fixed in)\s+([\w\s\-\.]{3,40}?)\s+(?:v?[\d]+\.[\d]+|version)",
        r"([\w\-\.]{3,30})\s+(?:v?[\d]+\.[\d]+\.[\d]+)",   # product 1.2.3 pattern
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

    # Also add same-paragraph co-occurrence as weaker chain signal
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
        markdown, re.I
    )

    return {
        "cves_mentioned":    cves,
        "cve_pairs":         cve_pairs[:100],      # cap at 100 pairs per page
        "cwes_mentioned":    cwes,
        "owasp_categories":  owasp,
        "cvss_scores_found": cvss_hits[:10],
        "mitre_techniques":  mitre_techs[:20],
        "affected_products": products,
        "exploit_chains":    chains[:50],
        "campaign_signals":  campaign_hits[:10],
        "severity_context":  severity_mentions[:10],
    }


def is_quality_content(text: str, keywords: list[str], min_chars: int) -> bool:
    stripped = text.strip()
    # If it has a CVE ID, always keep it regardless of length — short Vulhub
    # READMEs are valid and contain dense co-occurrence signal
    if re.search(r"CVE-\d{4}-\d+", stripped, re.I):
        return len(stripped) >= 50   # just needs to be non-empty
    if len(stripped) < min_chars:
        return False
    lower = stripped.lower()
    return any(kw in lower for kw in keywords)


def make_record(
    url: str,
    markdown: str,
    source_type: str,
    cfg: dict,
) -> dict:
    settings  = cfg.get("settings", {})
    max_chars = settings.get("max_content_chars", 10000)
    signals   = extract_correlation_signals(markdown, cfg)

    return {
        "url":         url,
        "source_type": source_type,
        "content":     markdown[:max_chars],
        **signals,      # unpack all correlation signals at top level
    }


# ══════════════════════════════════════════════════════════════════════════════
# CONCURRENT CRAWL  (crawl4ai with asyncio semaphore)
# ══════════════════════════════════════════════════════════════════════════════

async def crawl_url(
    crawler: AsyncWebCrawler,
    url: str,
    source_type: str,
    semaphore: asyncio.Semaphore,
    cfg: dict,
    idx: int,
    total: int,
) -> Optional[dict]:
    """Crawl a single URL under semaphore control."""
    settings  = cfg.get("settings", {})
    keywords  = cfg.get("quality_keywords", [])
    min_chars = settings.get("min_content_chars", 300)

    async with semaphore:
        try:
            run_cfg = CrawlerRunConfig(cache_mode=CacheMode.BYPASS)
            result  = await crawler.arun(url=url, config=run_cfg)

            if result.success and result.markdown:
                if is_quality_content(result.markdown, keywords, min_chars):
                    record  = make_record(url, result.markdown, source_type, cfg)
                    n_cves  = len(record["cves_mentioned"])
                    n_chains = len(record["exploit_chains"])
                    tags = []
                    if n_cves:     tags.append(f"{n_cves} CVEs")
                    if n_chains:   tags.append(f"{n_chains} chains")
                    tag_str = f" [{', '.join(tags)}]" if tags else ""
                    print(f"  ✅ [{idx}/{total}] {source_type:<25} {url[:55]}{tag_str}")
                    return record
                else:
                    print(f"  ⚠  [{idx}/{total}] Low quality: {url[:60]}")
            else:
                print(f"  ❌ [{idx}/{total}] Failed: {url[:60]}")

        except Exception as e:
            print(f"  ❌ [{idx}/{total}] Error ({url[:45]}): {e}")

    return None


async def crawl_all_concurrent(
    url_map: dict[str, str],    # {url: source_type}
    cfg: dict,
    concurrency: int,
) -> list[dict]:
    """
    Crawl all URLs concurrently using asyncio semaphore.
    `concurrency` = max simultaneous crawl4ai workers.
    """
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

    results = [r for r in raw_results if isinstance(r, dict)]

    # ── Summary stats ────────────────────────────────────────────────────────
    failed   = sum(1 for r in raw_results if r is None or isinstance(r, Exception))
    total_cves   = sum(len(r.get("cves_mentioned", [])) for r in results)
    total_pairs  = sum(len(r.get("cve_pairs", [])) for r in results)
    total_chains = sum(len(r.get("exploit_chains", [])) for r in results)
    total_camp   = sum(len(r.get("campaign_signals", [])) for r in results)
    total_cwes   = sum(len(r.get("cwes_mentioned", [])) for r in results)

    print(f"\n  ✔  {len(results)} pages kept  |  {failed} failed/filtered")
    print(f"  📊 Unique CVEs: {total_cves}  |  CVE pairs (co-occurrence): {total_pairs}")
    print(f"  📊 Exploit chains: {total_chains}  |  Campaign signals: {total_camp}  |  CWE mentions: {total_cwes}")

    return results


# ══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def build_url_map(discovered: dict[str, list[str]]) -> dict[str, str]:
    """Flatten {source_type: [urls]} → {url: source_type}, deduplicated."""
    url_map: dict[str, str] = {}
    for source_type, urls in discovered.items():
        for url in urls:
            if url not in url_map:
                url_map[url] = source_type
    return url_map


def infer_source_type(url: str) -> str:
    """Heuristic source_type for dynamically discovered URLs."""
    if "exploit-db.com" in url:             return "exploit_writeup"
    if "owasp.org" in url:                  return "owasp_guide"
    if "vulhub" in url:                     return "vulhub_writeup"
    if "portswigger" in url:               return "portswigger_research"
    if "rapid7.com" in url:                return "rapid7_blog"
    if "googleprojectzero" in url:         return "project_zero"
    if "snyk.io" in url or "wiz.io" in url: return "cloud_security_research"
    if "cisa.gov" in url:                  return "cisa_advisory"
    if "msrc.microsoft.com" in url:        return "msrc_advisory"
    if "github.com" in url:               return "github_advisory"
    if "hackerone.com" in url:             return "hackerone_disclosed"
    return "research_blog"


def run(
    config_path: Path,
    out_override: str | None = None,
    use_agent:   bool = True,
    use_vulhub:  bool = True,
    use_nvd:     bool = True,
    concurrency: int | None = None,
):
    cfg      = load_config(config_path)
    settings = cfg.get("settings", {})
    dyn      = cfg.get("dynamic", {})
    out_file = out_override or settings.get("output_file", "data/raw_blogs.json")
    workers  = concurrency or settings.get("concurrent_tasks", 10)
    max_total = settings.get("max_total_urls", 300)

    # ── 1. Agent: Google Search + Gemini discovery ──────────────────────────
    all_discovered: dict[str, list[str]] = {}
    if use_agent:
        llm_client, llm_models = init_llm(cfg)
        tavily = init_tavily(cfg)
        all_discovered = agent_discover_urls(cfg, llm_client, llm_models, tavily)
    else:
        print("\n  --no-agent: skipping Tavily + LLM discovery")

    url_map = build_url_map(all_discovered)

    # ── 2. Dynamic: Vulhub ──────────────────────────────────────────────────
    vulhub_cfg = dyn.get("vulhub", {})
    if use_vulhub and vulhub_cfg.get("enabled", True):
        for url in discover_vulhub_readmes(vulhub_cfg):
            if url not in url_map:
                url_map[url] = "vulhub_writeup"

    # ── 3. Dynamic: NVD refs ─────────────────────────────────────────────────
    nvd_cfg = dyn.get("nvd_references", {})
    if use_nvd and nvd_cfg.get("enabled", True):
        for url in harvest_nvd_reference_urls(nvd_cfg):
            if url not in url_map:
                url_map[url] = infer_source_type(url)

    # ── Cap ──────────────────────────────────────────────────────────────────
    if len(url_map) > max_total:
        print(f"  Capping at {max_total} URLs (had {len(url_map)})")
        url_map = dict(list(url_map.items())[:max_total])

    print(f"\n  Total unique URLs to crawl: {len(url_map)}")

    # ── 4. Concurrent crawl ──────────────────────────────────────────────────
    data = asyncio.run(crawl_all_concurrent(url_map, cfg, workers))

    # ── 5. Save ──────────────────────────────────────────────────────────────
    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # ── 6. Report ────────────────────────────────────────────────────────────
    source_counts: dict[str, int] = {}
    for d in data:
        st = d.get("source_type", "unknown")
        source_counts[st] = source_counts.get(st, 0) + 1

    total_pairs  = sum(len(d.get("cve_pairs", [])) for d in data)
    total_chains = sum(len(d.get("exploit_chains", [])) for d in data)
    total_camp   = sum(len(d.get("campaign_signals", [])) for d in data)
    cve_pages    = sum(1 for d in data if d.get("cves_mentioned"))
    pair_pages   = sum(1 for d in data if d.get("cve_pairs"))
    chain_pages  = sum(1 for d in data if d.get("exploit_chains"))
    camp_pages   = sum(1 for d in data if d.get("campaign_signals"))
    cwe_pages    = sum(1 for d in data if d.get("cwes_mentioned"))

    print(f"\n✅  Saved {len(data)} records → {out_file}")
    print(f"\n   Co-occurrence signal summary:")
    print(f"     Pages with ANY CVE mention:   {cve_pages}  (every one feeds co-occurrence)")
    print(f"     Total CVE pairs extracted:    {total_pairs}  (direct co-occurrence signals)")
    print(f"     Pages with exploit chains:    {chain_pages}  ({total_chains} chain pairs)")
    print(f"     Pages with campaign signals:  {camp_pages}  ({total_camp} sentences)")
    print(f"     Pages with CWE mentions:      {cwe_pages}  (shared_cwe signal)")
    print(f"\n   By source type:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"     {src:<30} {cnt}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic concurrent security blog crawler")
    parser.add_argument("--config",      default=str(DEFAULT_CONFIG))
    parser.add_argument("--out",         default=None, help="Override output path")
    parser.add_argument("--no-agent",    action="store_true", help="Skip Google Search")
    parser.add_argument("--no-vulhub",   action="store_true")
    parser.add_argument("--no-nvd-refs", action="store_true")
    parser.add_argument("--concurrency", type=int, default=None,
                        help="Override concurrent workers (default from sources.yaml)")
    args = parser.parse_args()

    run(
        config_path  = Path(args.config),
        out_override = args.out,
        use_agent    = not args.no_agent,
        use_vulhub   = not args.no_vulhub,
        use_nvd      = not args.no_nvd_refs,
        concurrency  = args.concurrency,
    )