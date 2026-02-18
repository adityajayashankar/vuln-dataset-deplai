"""
crawl_closed_sources.py
-----------------------
Crawls CLOSED and semi-private security data sources.
Goes beyond the public web to access:
- Security mailing list archives (Full Disclosure, Bugtraq)
- Bug bounty platform disclosures (HackerOne, Bugcrowd)
- Vendor security advisories (Microsoft MSRC - behind auth)
- Security forums and communities (Reddit /r/netsec, StackOverflow)
- CISA Known Exploited Vulnerabilities (KEV) catalog
- Vulners.com aggregated vulnerability database

Output: raw_closed.json

FIXES vs previous version:
  - BUG FIX: HACKERONE_API_TOKEN was defined as a URL string constant and then
    mistakenly used as both the request URL and the Bearer token value.
    Now correctly split into HACKERONE_API_URL + env var lookup.
  - BUG FIX: bs4 BeautifulSoup was imported inside the loop body — moved to top.
  - BUG FIX: Full Disclosure href filter was too loose — tightened to exclude
    navigation links ("#", "/", parent dirs).
  - NEW: crawl_cisa_kev() — free, no auth, highly curated exploitation data.
  - NEW: crawl_vulners() — aggregated vuln intel, requires free API key.
  - NEW: crawl_bugtraq() — historic Bugtraq SecurityFocus archive.
"""

import requests
import json
import re
import time
import os
from pathlib import Path
from datetime import datetime, timedelta
from tqdm import tqdm

# ── FIX: Import bs4 at module level, not inside function ──────────────────
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("⚠️  BeautifulSoup not found. Run: pip install beautifulsoup4")

# ── Constants (URLs only — tokens come from env vars) ─────────────────────
FULL_DISCLOSURE_ARCHIVE = "https://seclists.org/fulldisclosure"
HACKERONE_API_URL       = "https://api.hackerone.com/v1/hackers/reports"   # ← FIX: was mixed up with token
MSRC_API_URL            = "https://api.msrc.microsoft.com/cvrf/v2.0/cvrf"  # ← FIX: renamed for clarity
CISA_KEV_URL            = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VULNERS_SEARCH_URL      = "https://vulners.com/api/v3/search/lucene/"
BUGTRAQ_ARCHIVE         = "https://seclists.org/bugtraq"


# ── 1. CISA Known Exploited Vulnerabilities (FREE, no auth) ──────────────
def crawl_cisa_kev() -> list[dict]:
    """
    Download the CISA KEV catalog — a curated list of CVEs that are actively
    exploited in the wild. No authentication required.

    This is CLOSED/CURATED data: CISA analysts manually verify each entry,
    so every record has confirmed real-world exploitation evidence.
    Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
    """
    print("Fetching CISA Known Exploited Vulnerabilities catalog...")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        records = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID", "")
            records.append({
                "source":          "cisa_kev",
                "cve_id":          cve_id,
                "vendor":          vuln.get("vendorProject", ""),
                "product":         vuln.get("product", ""),
                "title":           vuln.get("vulnerabilityName", ""),
                "description":     vuln.get("shortDescription", ""),
                "action":          vuln.get("requiredAction", ""),
                "due_date":        vuln.get("dueDate", ""),
                "date_added":      vuln.get("dateAdded", ""),
                "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                "notes":           vuln.get("notes", ""),
                "cves_mentioned":  [cve_id] if cve_id else []
            })

        print(f"  ✅ CISA KEV: {len(records)} actively exploited CVEs")
        return records

    except Exception as e:
        print(f"  ⚠️  CISA KEV fetch failed: {e}")
        return []


# ── 2. Full Disclosure Mailing List ──────────────────────────────────────
def crawl_full_disclosure(months_back: int = 6, max_per_month: int = 50) -> list[dict]:
    """
    Crawl Full Disclosure mailing list archives from seclists.org.
    Contains real vulnerability disclosures, PoCs, and 0-day discussions
    that are NOT indexed well by search engines.
    """
    if not BS4_AVAILABLE:
        print("  ⚠️  Skipping Full Disclosure — beautifulsoup4 not installed.")
        return []

    print(f"Crawling Full Disclosure archives ({months_back} months back)...")
    posts = []
    today = datetime.now()

    for month_offset in range(months_back):
        target_date = today - timedelta(days=30 * month_offset)
        year        = target_date.year
        month_name  = target_date.strftime("%b")
        archive_url = f"{FULL_DISCLOSURE_ARCHIVE}/{year}/{month_name}/"

        try:
            print(f"  Fetching {year}/{month_name}...")
            resp = requests.get(archive_url, timeout=15)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            # FIX: Filter only actual post links — skip nav anchors and parent dirs
            post_links = [
                a["href"] for a in soup.find_all("a", href=True)
                if a["href"]
                and not a["href"].startswith("#")
                and not a["href"].startswith("/")
                and not a["href"].startswith("http")
                and a["href"] not in ("../", "./")
            ]

            for href in post_links[:max_per_month]:
                post_url = archive_url + href
                try:
                    post_resp = requests.get(post_url, timeout=10)
                    post_soup = BeautifulSoup(post_resp.text, "html.parser")
                    pre_tag   = post_soup.find("pre")
                    if pre_tag:
                        content = pre_tag.get_text()
                        cves    = list(set(re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)))
                        if cves:
                            posts.append({
                                "source":        "full_disclosure",
                                "url":           post_url,
                                "date":          f"{year}-{target_date.month:02d}",
                                "content":       content[:2000],
                                "cves_mentioned": cves
                            })
                    time.sleep(0.5)
                except Exception:
                    continue

            time.sleep(1)

        except Exception as e:
            print(f"  ⚠️  {year}/{month_name} failed: {e}")

    print(f"  ✅ Full Disclosure: {len(posts)} posts with CVE mentions")
    return posts


# ── 3. Bugtraq Archive ────────────────────────────────────────────────────
def crawl_bugtraq(months_back: int = 3, max_per_month: int = 30) -> list[dict]:
    """
    Crawl Bugtraq mailing list archive — one of the oldest and most respected
    vulnerability disclosure lists. Contains vendor patches, PoCs, advisories.
    Semi-closed: not easily accessible via standard search engines.
    """
    if not BS4_AVAILABLE:
        print("  ⚠️  Skipping Bugtraq — beautifulsoup4 not installed.")
        return []

    print(f"Crawling Bugtraq archives ({months_back} months back)...")
    posts = []
    today = datetime.now()

    for month_offset in range(months_back):
        target_date = today - timedelta(days=30 * month_offset)
        year        = target_date.year
        month_name  = target_date.strftime("%b")
        archive_url = f"{BUGTRAQ_ARCHIVE}/{year}/{month_name}/"

        try:
            resp = requests.get(archive_url, timeout=15)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")

            post_links = [
                a["href"] for a in soup.find_all("a", href=True)
                if a["href"]
                and not a["href"].startswith("#")
                and not a["href"].startswith("/")
                and not a["href"].startswith("http")
                and a["href"] not in ("../", "./")
            ]

            for href in post_links[:max_per_month]:
                post_url = archive_url + href
                try:
                    post_resp = requests.get(post_url, timeout=10)
                    post_soup = BeautifulSoup(post_resp.text, "html.parser")
                    pre_tag   = post_soup.find("pre")
                    if pre_tag:
                        content = pre_tag.get_text()
                        cves    = list(set(re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)))
                        if cves:
                            posts.append({
                                "source":         "bugtraq",
                                "url":            post_url,
                                "date":           f"{year}-{target_date.month:02d}",
                                "content":        content[:2000],
                                "cves_mentioned": cves
                            })
                    time.sleep(0.5)
                except Exception:
                    continue

            time.sleep(1)

        except Exception as e:
            print(f"  ⚠️  Bugtraq {year}/{month_name} failed: {e}")

    print(f"  ✅ Bugtraq: {len(posts)} posts with CVE mentions")
    return posts


# ── 4. HackerOne Public Disclosures ──────────────────────────────────────
def crawl_hackerone(max_reports: int = 100) -> list[dict]:
    """
    Fetch public vulnerability disclosures from HackerOne.
    Requires HackerOne account + API credentials (free to create).
    CLOSED data — requires authentication.

    BUG FIX: Previous version defined HACKERONE_API_TOKEN as the URL string,
    then used it as a Bearer token value. Now correctly split.

    Get API creds: https://hackerone.com/settings/api_token/edit
    Set env vars: HACKERONE_USERNAME and HACKERONE_API_TOKEN
    """
    username  = os.getenv("HACKERONE_USERNAME", "")
    api_token = os.getenv("HACKERONE_API_TOKEN", "")  # ← FIX: env var only, not hardcoded URL

    if not username or not api_token:
        print("  ⚠️  HackerOne credentials missing.")
        print("      Set: HACKERONE_USERNAME and HACKERONE_API_TOKEN env vars.")
        print("      Get token: https://hackerone.com/settings/api_token/edit")
        return []

    print("Fetching HackerOne public disclosures...")

    headers = {
        "Accept": "application/json",
        # FIX: HackerOne uses HTTP Basic auth (username:token), not Bearer
    }
    params = {
        "filter[state][]": "disclosed",
        "page[size]":      min(max_reports, 100),
        "sort":            "-disclosed_at"
    }

    try:
        resp = requests.get(
            HACKERONE_API_URL,
            auth=(username, api_token),   # ← FIX: Basic auth with username:token
            headers=headers,
            params=params,
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()

        reports = []
        for report in data.get("data", []):
            attrs   = report.get("attributes", {})
            title   = attrs.get("title", "")
            summary = attrs.get("vulnerability_information", "")
            cve_ids = attrs.get("cve_ids", [])

            if not cve_ids:
                cve_ids = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + summary, re.IGNORECASE)))

            reports.append({
                "source":          "hackerone",
                "report_id":       report.get("id", ""),
                "title":           title,
                "summary":         summary[:1500],
                "severity":        attrs.get("severity", {}).get("rating", ""),
                "disclosed_at":    attrs.get("disclosed_at", ""),
                "cves_mentioned":  cve_ids,
                "bounty_awarded":  attrs.get("bounty_awarded_at") is not None
            })

        print(f"  ✅ HackerOne: {len(reports)} disclosed reports")
        return reports

    except Exception as e:
        print(f"  ⚠️  HackerOne fetch failed: {e}")
        return []


# ── 5. Microsoft MSRC Advisories ─────────────────────────────────────────
def crawl_microsoft_advisories(max_advisories: int = 50) -> list[dict]:
    """
    Fetch Microsoft security advisories via MSRC API.
    Semi-closed — requires API key for full access.
    Contains vendor-specific vulnerability details not in NVD.

    Get API key: https://portal.msrc.microsoft.com/
    Set env var: MSRC_API_KEY
    """
    api_key = os.getenv("MSRC_API_KEY", "")
    if not api_key:
        print("  ⚠️  MSRC_API_KEY not set. Skipping Microsoft advisories.")
        print("      Get key: https://portal.msrc.microsoft.com/")
        return []

    print("Fetching Microsoft security advisories...")
    headers    = {"Accept": "application/json", "api-key": api_key}
    advisories = []
    year       = datetime.now().year

    for month in range(1, 13):
        update_id = f"{year}-{month:02d}"
        url       = f"{MSRC_API_URL}/{update_id}"
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            data  = resp.json()
            vulns = data.get("Vulnerability", [])

            for vuln in vulns:
                cve_id = vuln.get("CVE", "")
                if cve_id:
                    advisories.append({
                        "source":          "microsoft_msrc",
                        "cve_id":          cve_id,
                        "title":           vuln.get("Title", {}).get("Value", ""),
                        "description":     (vuln.get("Notes") or [{}])[0].get("Value", "")[:1500],
                        "severity":        (vuln.get("Threats") or [{}])[0].get("Description", {}).get("Value", ""),
                        "month":           update_id,
                        "cves_mentioned":  [cve_id]
                    })
            time.sleep(1)
        except Exception:
            continue

    print(f"  ✅ Microsoft MSRC: {len(advisories)} advisories")
    return advisories[:max_advisories]


# ── 6. Vulners.com API ────────────────────────────────────────────────────
def crawl_vulners(max_results: int = 200) -> list[dict]:
    """
    Fetch aggregated vulnerability intelligence from Vulners.com.
    Vulners aggregates NVD, vendor advisories, exploit-db, packetstorm,
    and many private sources — making it a rich closed/aggregated source.

    FREE API key: https://vulners.com/userinfo (register and get API key)
    Set env var: VULNERS_API_KEY
    """
    api_key = os.getenv("VULNERS_API_KEY", "")
    if not api_key:
        print("  ⚠️  VULNERS_API_KEY not set. Skipping Vulners.")
        print("      Free key: https://vulners.com/userinfo")
        return []

    print("Fetching Vulners.com vulnerability intelligence...")

    queries = [
        "type:cve AND cvss.score:[7 TO 10]",  # High/Critical CVEs
        "type:exploit",                         # Actual exploits
        "type:hackerone",                       # HackerOne disclosures via Vulners
        "type:packetstorm",                     # Packetstorm exploits
    ]

    records = []
    for query in queries:
        try:
            resp = requests.post(
                VULNERS_SEARCH_URL,
                json={
                    "query":  query,
                    "size":   min(max_results // len(queries), 100),
                    "apiKey": api_key
                },
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            for item in data.get("data", {}).get("search", []):
                src    = item.get("_source", {})
                cve_id = src.get("id", "")

                # Extract CVE IDs from content
                content = src.get("description", "") + " " + src.get("title", "")
                cves    = list(set(re.findall(r"CVE-\d{4}-\d+", content, re.IGNORECASE)))
                if cve_id.startswith("CVE-"):
                    cves = list(set([cve_id] + cves))

                if cves:
                    records.append({
                        "source":          f"vulners_{src.get('type', 'unknown')}",
                        "title":           src.get("title", ""),
                        "description":     src.get("description", "")[:2000],
                        "cvss_score":      src.get("cvss", {}).get("score", ""),
                        "published":       src.get("published", ""),
                        "href":            src.get("href", ""),
                        "cves_mentioned":  cves
                    })

            time.sleep(1)

        except Exception as e:
            print(f"  ⚠️  Vulners query failed ({query[:30]}): {e}")

    print(f"  ✅ Vulners: {len(records)} records")
    return records


# ── 7. Reddit /r/netsec ──────────────────────────────────────────────────
def crawl_reddit_netsec(max_posts: int = 100) -> list[dict]:
    """
    Deep scrape Reddit /r/netsec for vulnerability discussions.
    Requires Reddit app credentials (free).

    Setup: https://www.reddit.com/prefs/apps
    Set env vars: REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET
    """
    try:
        import praw

        client_id     = os.getenv("REDDIT_CLIENT_ID", "")
        client_secret = os.getenv("REDDIT_CLIENT_SECRET", "")

        if not client_id or not client_secret:
            print("  ⚠️  Reddit credentials not set. Skipping.")
            print("      Set: REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET")
            return []

        print("Crawling Reddit /r/netsec...")
        reddit    = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent="VulnResearchBot/1.0"
        )
        subreddit = reddit.subreddit("netsec+cybersecurity+AskNetsec")
        posts     = []

        for submission in subreddit.hot(limit=max_posts):
            title    = submission.title
            selftext = submission.selftext
            cves     = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + selftext, re.IGNORECASE)))

            if cves:
                submission.comments.replace_more(limit=0)
                top_comments = " ".join([c.body for c in list(submission.comments)[:5]])
                posts.append({
                    "source":          "reddit_netsec",
                    "post_id":         submission.id,
                    "title":           title,
                    "content":         (selftext + " " + top_comments)[:2000],
                    "url":             f"https://reddit.com{submission.permalink}",
                    "score":           submission.score,
                    "created":         datetime.fromtimestamp(submission.created_utc).isoformat(),
                    "cves_mentioned":  cves
                })

        print(f"  ✅ Reddit: {len(posts)} posts with CVEs")
        return posts

    except ImportError:
        print("  ⚠️  praw not installed. Run: pip install praw")
        return []
    except Exception as e:
        print(f"  ⚠️  Reddit crawl failed: {e}")
        return []


# ── 8. StackOverflow Security Tag ─────────────────────────────────────────
def crawl_stackoverflow_security(max_questions: int = 50) -> list[dict]:
    """
    Scrape StackOverflow security-tagged questions for vulnerability discussions.
    Uses StackExchange API — free but rate-limited.
    """
    SO_API = "https://api.stackexchange.com/2.3/search/advanced"
    print("Crawling StackOverflow security questions...")

    params = {
        "order":    "desc",
        "sort":     "votes",
        "tagged":   "security;vulnerability",
        "site":     "stackoverflow",
        "pagesize": max_questions,
        "filter":   "withbody"
    }

    try:
        resp = requests.get(SO_API, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        questions = []
        for item in data.get("items", []):
            title = item.get("title", "")
            body  = item.get("body", "")
            cves  = list(set(re.findall(r"CVE-\d{4}-\d+", title + " " + body, re.IGNORECASE)))

            if cves:
                questions.append({
                    "source":          "stackoverflow",
                    "question_id":     item.get("question_id", ""),
                    "title":           title,
                    "body":            body[:1500],
                    "score":           item.get("score", 0),
                    "url":             item.get("link", ""),
                    "cves_mentioned":  cves
                })

        print(f"  ✅ StackOverflow: {len(questions)} questions with CVEs")
        return questions

    except Exception as e:
        print(f"  ⚠️  StackOverflow crawl failed: {e}")
        return []


# ── Main ───────────────────────────────────────────────────────────────────
def run(out: str = "data/raw_closed.json"):
    """
    Aggregate all CLOSED and semi-private data sources.
    Some sources require API credentials — set the relevant env vars
    or copy them into a .env file (never commit credentials to git).
    """
    all_data: list[dict] = []

    print("\n🔒 Crawling CLOSED and semi-private security sources...\n")

    # 1. CISA KEV — always works, no auth needed, highest-value data
    kev_records = crawl_cisa_kev()
    all_data.extend(kev_records)
    time.sleep(1)

    # 2. Full Disclosure mailing list
    fd_posts = crawl_full_disclosure(months_back=3, max_per_month=20)
    all_data.extend(fd_posts)
    time.sleep(2)

    # 3. Bugtraq archive
    bt_posts = crawl_bugtraq(months_back=3, max_per_month=20)
    all_data.extend(bt_posts)
    time.sleep(2)

    # 4. HackerOne public disclosures (requires HACKERONE_USERNAME + HACKERONE_API_TOKEN)
    h1_reports = crawl_hackerone(max_reports=50)
    all_data.extend(h1_reports)
    time.sleep(2)

    # 5. Microsoft MSRC (requires MSRC_API_KEY)
    ms_advisories = crawl_microsoft_advisories(max_advisories=30)
    all_data.extend(ms_advisories)
    time.sleep(2)

    # 6. Vulners.com (requires VULNERS_API_KEY — free to register)
    vulners_records = crawl_vulners(max_results=200)
    all_data.extend(vulners_records)
    time.sleep(2)

    # 7. Reddit /r/netsec (requires REDDIT_CLIENT_ID + REDDIT_CLIENT_SECRET)
    reddit_posts = crawl_reddit_netsec(max_posts=50)
    all_data.extend(reddit_posts)
    time.sleep(2)

    # 8. StackOverflow (no auth needed)
    so_questions = crawl_stackoverflow_security(max_questions=30)
    all_data.extend(so_questions)

    # Keep only records with CVE mentions
    data_with_cves = [d for d in all_data if d.get("cves_mentioned")]

    # Statistics
    source_counts: dict[str, int] = {}
    for item in data_with_cves:
        src = item.get("source", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    print(f"\n✅ Total records collected:     {len(all_data)}")
    print(f"✅ Records with CVE mentions:   {len(data_with_cves)}")
    print("\nBreakdown by source:")
    for source, count in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"  - {source:<30} {count:>4} records")

    with open(out, "w", encoding="utf-8") as f:
        json.dump(data_with_cves, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Saved {len(data_with_cves)} closed-source records → {out}")


if __name__ == "__main__":
    if not BS4_AVAILABLE:
        print("⚠️  Install: pip install beautifulsoup4 praw")

    # Load .env file if present (never commit .env to git)
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

    run()