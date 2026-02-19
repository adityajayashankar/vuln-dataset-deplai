"""
crawl_blogs.py  (FIXED)
--------------------------
Crawls security research blogs and write-ups for real attack context.
Uses Crawl4AI — auto-converts HTML → clean Markdown.

FIXES in this version:
  1. Incremental saving: Writes to raw_blogs.json immediately after every successful crawl.
  2. Safe CVSS parsing: Prevents ValueError crashes on "N/A" NVD scores.
"""

import asyncio
import json
import re
import requests
from pathlib import Path
from crawl4ai import AsyncWebCrawler

# ── Category 1: Exploit write-ups (Exploit-DB) ────────────────────────────
EXPLOITDB_URLS = [
    "https://www.exploit-db.com/exploits/51893",
    "https://www.exploit-db.com/exploits/51839",
    "https://www.exploit-db.com/exploits/51777",
    "https://www.exploit-db.com/exploits/51708",
    "https://www.exploit-db.com/exploits/51665",
    "https://www.exploit-db.com/exploits/51535",
    "https://www.exploit-db.com/exploits/51467",
    "https://www.exploit-db.com/exploits/51334",
    "https://www.exploit-db.com/exploits/51214",
    "https://www.exploit-db.com/exploits/51092",
]

# ── Category 2: OWASP Testing Guide sections ──────────────────────────────
OWASP_WSTG_URLS = [
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_XML_Injection",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
]

# ── Category 3: Vulhub CVE write-ups (GitHub raw markdown) ────────────────
VULHUB_STATIC_URLS = [
    "https://raw.githubusercontent.com/vulhub/vulhub/master/log4j/CVE-2021-44228/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/shiro/CVE-2016-4437/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/struts2/CVE-2017-5638/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/spring/CVE-2022-22965/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/weblogic/CVE-2019-2725/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/fastjson/CVE-2017-18349/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/drupal/CVE-2018-7600/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/phpunit/CVE-2017-9841/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/jenkins/CVE-2018-1000861/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/php/CVE-2019-11043/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/confluence/CVE-2022-26134/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/exchange/CVE-2021-26855/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/solr/CVE-2019-0193/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/tomcat/CVE-2017-12615/README.md",
    "https://raw.githubusercontent.com/vulhub/vulhub/master/redis/4-unacc/README.md",
]

# ── Category 4: PortSwigger Research ─────────────────────────────────────
PORTSWIGGER_URLS = [
    "https://portswigger.net/research/server-side-template-injection",
    "https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn",
    "https://portswigger.net/research/web-cache-poisoning",
    "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties",
    "https://portswigger.net/research/prototype-pollution",
    "https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface",
]

# ── Category 5: Rapid7 / AttackerKB ──────────────────────────────────────
RAPID7_URLS = [
    "https://www.rapid7.com/blog/post/2021/12/10/log4shell-cve-2021-44228-exploiting-critical-apache-log4j/",
    "https://www.rapid7.com/blog/post/2022/04/14/spring4shell-cve-2022-22965-exploited-in-the-wild/",
    "https://www.rapid7.com/blog/post/2022/01/18/cve-2021-26084-confluence-ognl-injection-added-to-metasploit/",
    "https://www.rapid7.com/blog/post/2023/02/02/cve-2023-22952-improper-input-validation-in-suitecrm/",
]

# ── Category 6: Project Zero (Google) ────────────────────────────────────
PROJECT_ZERO_URLS = [
    "https://googleprojectzero.blogspot.com/2021/12/a-look-at-imessage-in-ios-14.html",
    "https://googleprojectzero.blogspot.com/2022/04/the-chromium-super-inline-cache-type.html",
    "https://googleprojectzero.blogspot.com/2020/09/attacking-weakly-entropy-windows.html",
]

# ── Category 7: Cloud / Supply Chain Research ─────────────────────────────
CLOUD_RESEARCH_URLS = [
    "https://snyk.io/blog/zip-slip-vulnerability/",
    "https://snyk.io/blog/prototype-pollution-lodash/",
    "https://snyk.io/blog/prototype-pollution-minimist/",
    "https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-cache-poisoning",
]

# ── Category 8: CISA Advisories ───────────────────────────────────────────
CISA_ADVISORY_URLS = [
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-279a",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-320a",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a",
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a",
]

TARGET_URLS = (
    EXPLOITDB_URLS + OWASP_WSTG_URLS + VULHUB_STATIC_URLS +
    PORTSWIGGER_URLS + RAPID7_URLS + PROJECT_ZERO_URLS +
    CLOUD_RESEARCH_URLS + CISA_ADVISORY_URLS
)

SECURITY_KEYWORDS = [
    "cve", "vulnerability", "exploit", "payload", "injection", "overflow",
    "rce", "xss", "sqli", "ssrf", "bypass", "poc", "deserialization",
    "privilege escalation", "remote code", "authentication bypass",
]


def discover_vulhub_readmes(max_readmes: int = 80) -> list[str]:
    """Hit GitHub Tree API to find ALL Vulhub CVE README.md files dynamically."""
    print("  Discovering Vulhub CVE READMEs via GitHub Tree API...")
    try:
        resp = requests.get(
            "https://api.github.com/repos/vulhub/vulhub/git/trees/master?recursive=1",
            timeout=20,
            headers={"Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        tree = resp.json().get("tree", [])
        cve_readmes = [
            item["path"] for item in tree
            if item["path"].endswith("README.md")
            and re.search(r"CVE-\d{4}-\d+", item["path"])
        ]
        raw_urls = [
            f"https://raw.githubusercontent.com/vulhub/vulhub/master/{path}"
            for path in cve_readmes[:max_readmes]
        ]
        print(f"  Discovered {len(raw_urls)} Vulhub CVE READMEs")
        return raw_urls
    except Exception as e:
        print(f"  Vulhub discovery failed: {e} — using static list")
        return []


def harvest_nvd_reference_urls(
    nvd_path: str = "data/raw_nvd.json",
    max_total: int = 150,
) -> list[str]:
    """
    Pull reference blog/advisory URLs from high-CVSS NVD records.
    Gives per-CVE write-ups automatically without manual curation.
    """
    allowed_domains = [
        "blog.", "research.", "portswigger", "rapid7", "qualys",
        "tenable", "snyk", "github.com/", "exploit-db", "packetstorm",
        "security.googleblog", "googleprojectzero",
    ]
    p = Path(nvd_path)
    if not p.exists():
        return []
    with open(p, encoding="utf-8") as f:
        records = json.load(f)

    # Safe float parsing to prevent ValueError crashes
    def get_cvss(r):
        try:
            return float(r.get("cvss_score") or 0)
        except (ValueError, TypeError):
            return 0.0

    prioritised = sorted(
        [r for r in records if r.get("cvss_score")],
        key=get_cvss,
        reverse=True,
    )[:500]

    urls, seen = [], set()
    for rec in prioritised:
        for ref in rec.get("references", []):
            url = ref if isinstance(ref, str) else ref.get("url", "")
            if not url or url in seen:
                continue
            if any(d in url for d in allowed_domains):
                urls.append(url)
                seen.add(url)
        if len(urls) >= max_total:
            break

    print(f"  Harvested {len(urls)} reference URLs from high-CVSS NVD records")
    return urls


def is_quality_content(markdown: str) -> bool:
    if len(markdown.strip()) < 200:
        return False
    return any(kw in markdown.lower() for kw in SECURITY_KEYWORDS)


def classify_blog_record(url: str, markdown: str) -> dict:
    if "exploit-db.com" in url:         source_type = "exploit_writeup"
    elif "owasp.org" in url:            source_type = "owasp_guide"
    elif "vulhub" in url:               source_type = "vulhub_writeup"
    elif "portswigger" in url:          source_type = "portswigger_research"
    elif "rapid7" in url:               source_type = "rapid7_blog"
    elif "googleprojectzero" in url:    source_type = "project_zero"
    elif "snyk" in url or "wiz.io" in url: source_type = "cloud_security_research"
    elif "cisa.gov" in url:             source_type = "cisa_advisory"
    else:                               source_type = "research_blog"

    cves = list(set(re.findall(r"CVE-\d{4}-\d+", markdown, re.IGNORECASE)))
    return {"url": url, "source_type": source_type, "cves_mentioned": cves, "content": markdown[:8000]}


async def crawl_all(urls: list[str], out_file: str, delay: float = 1.2) -> list[dict]:
    results, failed, filtered = [], 0, 0
    async with AsyncWebCrawler(verbose=False) as crawler:
        for i, url in enumerate(urls):
            try:
                result = await crawler.arun(url=url)
                if result.success and result.markdown:
                    if is_quality_content(result.markdown):
                        record = classify_blog_record(url, result.markdown)
                        results.append(record)
                        cve_tag = f" [{','.join(record['cves_mentioned'][:2])}]" if record["cves_mentioned"] else ""
                        print(f"  ✅ [{i+1}/{len(urls)}] {url[:70]}{cve_tag}")
                        
                        # FIX: Save incrementally. If the script gets interrupted, your data is safe.
                        with open(out_file, "w", encoding="utf-8") as f:
                            json.dump(results, f, indent=2, ensure_ascii=False)
                    else:
                        filtered += 1
                else:
                    failed += 1
                    print(f"  ❌ [{i+1}/{len(urls)}] Failed: {url[:60]}")
                await asyncio.sleep(delay)
            except Exception as e:
                failed += 1
                print(f"  ❌ Error ({url[:50]}): {e}")

    print(f"\n  {len(results)} kept | {filtered} filtered (low quality) | {failed} failed")
    return results


def run(
    out: str = "data/raw_blogs.json",
    discover_vulhub: bool = True,
    harvest_nvd_refs: bool = True,
    max_vulhub: int = 80,
    max_nvd_refs: int = 100,
    crawl_delay: float = 1.2,
):
    # Ensure the data directory exists
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    
    all_urls = list(TARGET_URLS)

    if discover_vulhub:
        dynamic = discover_vulhub_readmes(max_readmes=max_vulhub)
        existing = set(all_urls)
        new = [u for u in dynamic if u not in existing]
        all_urls.extend(new)
        print(f"  +{len(new)} dynamic Vulhub URLs (static had {len(VULHUB_STATIC_URLS)})")

    if harvest_nvd_refs:
        nvd_refs = harvest_nvd_reference_urls(max_total=max_nvd_refs)
        existing = set(all_urls)
        new = [u for u in nvd_refs if u not in existing]
        all_urls.extend(new)
        print(f"  +{len(new)} NVD reference URLs")

    all_urls = list(dict.fromkeys(all_urls))
    print(f"\nCrawling {len(all_urls)} security sources...")

    # Passed 'out' directly into the crawler so it can save incrementally
    data = asyncio.run(crawl_all(all_urls, out_file=out, delay=crawl_delay))

    cve_tagged = sum(1 for d in data if d.get("cves_mentioned"))
    source_counts: dict = {}
    for d in data:
        st = d.get("source_type", "unknown")
        source_counts[st] = source_counts.get(st, 0) + 1

    print(f"\n✅ Finished crawling. Data is stored in → {out}")
    print(f"   With CVE mentions: {cve_tagged}")
    print("\n   By source type:")
    for src, cnt in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"     {src:<30} {cnt}")


if __name__ == "__main__":
    run()