"""
crawl_papers.py  (FIXED)
------------------------
FIXES:
  1. OSV 400 Bad Request — the query endpoint requires a package name+ecosystem,
     not just ecosystem. Now uses OSV's ZIP data dumps (correct bulk access method).
  2. Semantic Scholar 429 — added exponential backoff retry.
  3. arXiv returning 0 CVE matches — abstracts rarely contain CVE IDs. Now uses
     CVE-focused search queries + full-text PDF extraction.
"""

import requests
import json
import re
import time
import os
import zipfile
import io
from pathlib import Path

ARXIV_API    = "http://export.arxiv.org/api/query"
SEMANTIC_API = "https://api.semanticscholar.org/graph/v1/paper/search"


def with_retry(fn, max_retries=4, base_delay=5, max_delay=30):
    """
    Call fn(); on 429/5xx retry with exponential backoff capped at max_delay.
    Delays: 5s → 10s → 20s → 30s (capped, never exceeds 30s).
    Does NOT keep retrying forever — gives up after max_retries attempts.
    """
    for attempt in range(max_retries):
        try:
            return fn()
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response else 0
            if code in (429, 500, 502, 503) and attempt < max_retries - 1:
                delay = min(base_delay * (2 ** attempt), max_delay)  # cap at 30s
                print(f"    Rate limited ({code}). Waiting {delay}s (attempt {attempt+1}/{max_retries})...")
                time.sleep(delay)
            else:
                raise
    return None


def search_arxiv(max_results: int = 100) -> list:
    import xml.etree.ElementTree as ET

    # FIX: Use queries that will actually find papers mentioning CVE IDs
    queries = [
        "CVE-202",
        "exploit vulnerability proof of concept",
        "zero-day remote code execution vulnerability",
        "SQL injection cross-site scripting attack",
    ]

    all_papers = []
    per_query  = max_results // len(queries)

    # FIX: Sleep BEFORE the loop starts too — arXiv bans bursts from prior runs.
    # The first query (i=0) was getting 429 because `if i > 0` skipped the sleep.
    print("  (Waiting 15s before arXiv to avoid burst rate limit...)")
    time.sleep(15)

    for i, query in enumerate(queries):
        if i > 0:
            time.sleep(15)   # 15s between queries

        params = {
            "search_query": f"cat:cs.CR AND all:{query}",
            "start":        0,
            "max_results":  per_query,
            "sortBy":       "submittedDate",
            "sortOrder":    "descending"
        }
        try:
            resp = with_retry(lambda p=params: requests.get(ARXIV_API, params=p, timeout=30))
            if resp is None:
                continue
            resp.raise_for_status()
            root = ET.fromstring(resp.content)
            ns   = {"atom": "http://www.w3.org/2005/Atom"}

            for entry in root.findall("atom:entry", ns):
                title     = entry.find("atom:title", ns).text.strip().replace("\n", " ")
                summary   = entry.find("atom:summary", ns).text.strip()
                published = entry.find("atom:published", ns).text.strip()
                arxiv_id  = entry.find("atom:id", ns).text.split("/")[-1]
                cves      = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + summary, re.IGNORECASE)))

                all_papers.append({
                    "source":         "arxiv",
                    "arxiv_id":       arxiv_id,
                    "title":          title,
                    "abstract":       summary,
                    "published":      published[:10],
                    "pdf_url":        f"https://arxiv.org/pdf/{arxiv_id}.pdf",
                    "cves_mentioned": cves
                })
        except Exception as e:
            print(f"  \u26a0\ufe0f  arXiv query '{query}' failed: {e}")

    seen, unique = set(), []
    for p in all_papers:
        if p["arxiv_id"] not in seen:
            seen.add(p["arxiv_id"])
            unique.append(p)

    print(f"  ✅ arXiv: {len(unique)} papers ({sum(1 for p in unique if p['cves_mentioned'])} with CVEs)")
    return unique


def search_semantic_scholar(max_results: int = 80) -> list:
    print("Searching Semantic Scholar for security papers...")

    headers = {}
    api_key = os.getenv("SEMANTIC_SCHOLAR_API_KEY", "")
    if api_key:
        headers["x-api-key"] = api_key

    fields  = "title,abstract,year,externalIds,openAccessPdf"
    queries = [
        "CVE vulnerability exploit proof of concept",
        "ransomware malware attack technique analysis",
        "penetration testing vulnerability discovery",
    ]

    # FIX: Semantic Scholar public API allows 1 req/sec unauthenticated.
    # Hitting 3 queries back-to-back causes immediate 429.
    # Sleep 15s before starting, 15s between queries.
    print("  (Waiting 20s before Semantic Scholar to avoid rate limit...)")
    time.sleep(20)

    papers = []
    for qi, query in enumerate(queries):
        if qi > 0:
            time.sleep(20)   # 20s between queries
        offset = 0
        while len(papers) < max_results // len(queries):
            def do_req(q=query, o=offset):
                return requests.get(
                    SEMANTIC_API,
                    params={"query": q, "fields": fields, "limit": 25, "offset": o},
                    headers=headers,
                    timeout=30
                )
            try:
                resp = with_retry(do_req, max_retries=3, base_delay=15, max_delay=30)
                if resp is None:
                    break
                resp.raise_for_status()
                items = resp.json().get("data", [])
                if not items:
                    break

                for item in items:
                    abstract = item.get("abstract") or ""
                    title    = item.get("title") or ""
                    cves     = list(set(re.findall(r"CVE-\d{4}-\d+", abstract + " " + title, re.IGNORECASE)))
                    pdf_url  = (item.get("openAccessPdf") or {}).get("url", "")

                    papers.append({
                        "source":         "semantic_scholar",
                        "paper_id":       item.get("paperId", ""),
                        "title":          title,
                        "abstract":       abstract,
                        "published":      str(item.get("year", "")),
                        "pdf_url":        pdf_url,
                        "cves_mentioned": cves
                    })

                offset += len(items)
                if len(items) < 25:
                    break
                time.sleep(5)   # between pages of same query
            except Exception as e:
                print(f"  ⚠️  Semantic Scholar failed: {e}")
                break
        time.sleep(3)

    seen, unique = set(), []
    for p in papers:
        pid = p.get("paper_id") or p.get("title", "")[:80]
        if pid not in seen:
            seen.add(pid)
            unique.append(p)

    print(f"  ✅ Semantic Scholar: {len(unique)} papers ({sum(1 for p in unique if p['cves_mentioned'])} with CVEs)")
    return unique


def crawl_osv_by_ecosystem(ecosystems: list = None) -> list:
    """
    FIX: Use OSV's official ecosystem ZIP data dumps.
    Previous version sent a malformed API payload — the /v1/query endpoint
    requires a package name, not just ecosystem. The correct bulk method
    is downloading per-ecosystem ZIP files from GCS.
    Each ZIP contains one JSON file per vulnerability.
    """
    if ecosystems is None:
        ecosystems = ["PyPI", "npm", "Go", "Maven", "NuGet"]

    print(f"Downloading OSV ecosystem ZIP dumps ({len(ecosystems)} ecosystems)...")
    records = []

    for ecosystem in ecosystems:
        zip_url = f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
        try:
            print(f"  Fetching OSV/{ecosystem}...")
            resp = requests.get(zip_url, timeout=60, stream=True)
            if resp.status_code != 200:
                print(f"  ⚠️  OSV {ecosystem} returned {resp.status_code}")
                continue

            zf    = zipfile.ZipFile(io.BytesIO(resp.content))
            count = 0

            for fname in zf.namelist()[:300]:  # 300 per ecosystem
                try:
                    vuln    = json.loads(zf.read(fname))
                    vuln_id = vuln.get("id", "")
                    aliases = vuln.get("aliases", [])
                    summary = vuln.get("summary", "")
                    details = vuln.get("details", "")

                    cves = [a for a in aliases if a.startswith("CVE-")]
                    if not cves:
                        cves = list(set(re.findall(r"CVE-\d{4}-\d+", details + " " + summary, re.IGNORECASE)))

                    if cves:
                        records.append({
                            "source":         "osv",
                            "osv_id":         vuln_id,
                            "ecosystem":      ecosystem,
                            "title":          summary,
                            "description":    details[:2000],
                            "published":      vuln.get("published", "")[:10],
                            "cves_mentioned": cves
                        })
                        count += 1
                except Exception:
                    continue

            print(f"    ✅ {ecosystem}: {count} records with CVEs")
            time.sleep(1)

        except Exception as e:
            print(f"  ⚠️  OSV {ecosystem} ZIP failed: {e}")

    print(f"  ✅ OSV total: {len(records)} records")
    return records


def extract_text_from_pdf(pdf_url: str) -> str:
    try:
        try:
            from pypdf import PdfReader
        except ImportError:
            from PyPDF2 import PdfReader
        from io import BytesIO
        resp = requests.get(pdf_url, timeout=30,
                            headers={"User-Agent": "VulnResearchBot/1.0"})
        resp.raise_for_status()
        reader = PdfReader(BytesIO(resp.content))
        return "".join(p.extract_text() or "" for p in reader.pages[:10])[:5000]
    except Exception:
        return ""


def enrich_papers_with_fulltext(papers: list, max_enrich: int = 30) -> int:
    """Extract CVE IDs from full PDF text — abstracts rarely contain them."""
    enriched = 0
    for paper in papers[:max_enrich]:
        if not paper.get("pdf_url") or paper.get("fulltext_extracted"):
            continue
        fulltext = extract_text_from_pdf(paper["pdf_url"])
        if fulltext:
            new_cves = list(set(re.findall(r"CVE-\d{4}-\d+", fulltext, re.IGNORECASE)))
            before   = len(paper.get("cves_mentioned", []))
            paper["cves_mentioned"]     = list(set(paper.get("cves_mentioned", []) + new_cves))
            paper["fulltext_sample"]    = fulltext[:1000]
            paper["fulltext_extracted"] = True
            if len(paper["cves_mentioned"]) > before:
                enriched += 1
        time.sleep(1.5)
    return enriched


def run(out: str = "data/raw_papers.json"):
    all_papers: list = []

    arxiv_papers = search_arxiv(max_results=100)
    all_papers.extend(arxiv_papers)
    time.sleep(1)

    ss_papers = search_semantic_scholar(max_results=80)
    all_papers.extend(ss_papers)
    time.sleep(1)

    osv_records = crawl_osv_by_ecosystem()
    all_papers.extend(osv_records)

    # Deduplicate by title
    seen_titles, unique_papers = set(), []
    for p in all_papers:
        key = p.get("title", "").lower().strip()[:80]
        if key and key not in seen_titles:
            seen_titles.add(key)
            unique_papers.append(p)

    print("\nEnriching open-access papers with full-text CVE extraction...")
    enriched_count = enrich_papers_with_fulltext(unique_papers, max_enrich=30)

    papers_with_cves = [p for p in unique_papers if p.get("cves_mentioned")]
    total_cve_mentions = sum(len(p.get("cves_mentioned", [])) for p in unique_papers)

    print(f"\n📄 Total unique records:    {len(unique_papers)}")
    print(f"📄 With CVE mentions:       {len(papers_with_cves)}")
    print(f"   Full-text enriched:      {enriched_count}")
    print(f"   Total CVE mentions:      {total_cve_mentions}")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(unique_papers, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved {len(unique_papers)} research records → {out}")


if __name__ == "__main__":
    run()