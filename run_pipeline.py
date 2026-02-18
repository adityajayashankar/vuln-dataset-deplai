#!/usr/bin/env python3
"""
run_pipeline.py
---------------
Master script — runs all crawlers in the correct order, then builds the dataset.

Usage:
    python run_pipeline.py              # full pipeline
    python run_pipeline.py --open-only  # skip closed/auth-required sources
    python run_pipeline.py --from-build # skip crawling, only rebuild dataset

Order:
    1. NVD          → data/raw_nvd.json
    2. EPSS         → data/raw_epss.json       (requires raw_nvd.json)
    3. GitHub       → data/raw_github.json
    4. Blogs        → data/raw_blogs.json
    5. Exploit-DB   → data/raw_exploitdb.json  (bulk CSV, no auth)
    6. CISA KEV     → data/raw_cisa_kev.json   (no auth, high value)
    7. Papers       → data/raw_papers.json     (arXiv + Semantic Scholar + OSV)
    8. Closed       → data/raw_closed.json     (requires API keys)
    9. Build        → data/vuln_dataset.jsonl + data/training_pairs.jsonl
"""

import sys
import argparse
import time
from pathlib import Path

# Ensure data/ directory on path for module imports
sys.path.insert(0, str(Path(__file__).parent / "data"))


def step(label: str, fn, *args, **kwargs):
    """Run a pipeline step with timing and error isolation."""
    print(f"\n{'='*60}")
    print(f"  STEP: {label}")
    print(f"{'='*60}")
    t0 = time.time()
    try:
        fn(*args, **kwargs)
        elapsed = time.time() - t0
        print(f"\n  ✅ {label} done in {elapsed:.1f}s")
    except Exception as e:
        print(f"\n  ❌ {label} FAILED: {e}")
        import traceback
        traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="Vulnerability dataset pipeline")
    parser.add_argument("--open-only",   action="store_true", help="Skip closed/auth sources")
    parser.add_argument("--from-build",  action="store_true", help="Skip crawling, rebuild dataset only")
    parser.add_argument("--nvd-total",   type=int, default=10000, help="NVD records to fetch")
    args = parser.parse_args()

    Path("data").mkdir(exist_ok=True)

    if not args.from_build:
        # ── Open sources (no credentials needed) ──────────────────────────
        from data.crawl_nvd import run as run_nvd
        step("NVD CVE Database", run_nvd, total=args.nvd_total)

        from data.crawl_epss import run as run_epss
        step("EPSS Exploit Scores", run_epss)

        from data.crawl_github import run as run_github
        step("GitHub Security Advisories", run_github)

        from data.crawl_blogs import run as run_blogs
        step("Security Blogs (Exploit-DB / OWASP / Vulhub)", run_blogs)

        from data.crawl_exploitdb import run as run_exploitdb
        step("Exploit-DB Bulk CSV", run_exploitdb)

        from data.crawl_cisa_kev import run as run_kev
        step("CISA Known Exploited Vulnerabilities", run_kev)

        from data.crawl_papers import run as run_papers
        step("Research Papers (arXiv + Semantic Scholar + OSV)", run_papers)

        if not args.open_only:
            # ── Closed / auth-required sources ────────────────────────────
            from data.crawl_closed_sources import run as run_closed
            step("Closed Sources (KEV/HackerOne/MSRC/Full Disclosure)", run_closed)

    # ── Build dataset from all raw files ──────────────────────────────────
    from data.build_dataset import run as run_build
    step("Build Dataset (merge + training pairs)", run_build)

    print(f"\n{'='*60}")
    print("  🚀 Pipeline complete!")
    print(f"{'='*60}")
    print("  Outputs:")
    print("    data/vuln_dataset.jsonl    — full schema records")
    print("    data/training_pairs.jsonl  — fine-tuning pairs")
    print("\n  Next step: python training/finetuning.py")


if __name__ == "__main__":
    main()