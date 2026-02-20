#!/usr/bin/env python3
"""
run_pipeline.py
---------------
Master script — runs all crawlers in the correct order, then builds the dataset.

FIX: All file paths now use pathlib.Path to avoid Windows backslash separator bugs.
     'data\\raw_blogs.json' style strings are gone; Path('data') / 'raw_blogs.json'
     is used everywhere — works on Win32, Linux, macOS identically.

Usage:
    python run_pipeline.py              # full pipeline
    python run_pipeline.py --open-only  # skip closed/auth-required sources
    python run_pipeline.py --from-build # skip crawling, only rebuild dataset
    python run_pipeline.py --correlate  # (re)run correlation step then rebuild
    python run_pipeline.py --synthetic  # (re)run synthetic pair generation only

Order:
    1.  NVD               -> data/raw_nvd.json
    2.  EPSS              -> data/raw_epss.json
    3.  GitHub            -> data/raw_github.json
    4.  Blogs             -> data/raw_blogs.json
    5.  Exploit-DB        -> data/raw_exploitdb.json
    6.  CISA KEV          -> data/raw_cisa_kev.json
    7.  Papers            -> data/raw_papers.json
    8.  MITRE ATT&CK      -> data/raw_mitre_attack.json
    9.  Vendor Advisories -> data/raw_vendor_advisories.json
   10.  Closed Sources    -> data/raw_closed.json
   11.  Correlations      -> data/raw_correlations.json
   12.  Co-occurrence     -> data/raw_cooccurrence.json
   13.  Build             -> data/vuln_dataset.jsonl + data/training_pairs.jsonl
   14.  Synthetic Pairs   -> appended to data/training_pairs.jsonl (only if thin layers)
"""

import sys
import argparse
import time
from pathlib import Path

# ── Canonical data directory ───────────────────────────────────────────────
# Using Path objects throughout eliminates Windows backslash separator bugs.
# Never use string literals like 'data\\raw_blogs.json'.
DATA_DIR          = Path("data")
TRAINING_PAIRS    = DATA_DIR / "training_pairs.jsonl"
VULN_DATASET      = DATA_DIR / "vuln_dataset.jsonl"

sys.path.insert(0, str(Path(__file__).parent / "data"))

# ── Load .env BEFORE anything else ────────────────────────────────────────
try:
    from dotenv import load_dotenv
    env_file = Path(".env")
    if env_file.exists():
        load_dotenv(dotenv_path=env_file, override=True)
        print("Loaded .env")
    else:
        print("No .env file found — using shell environment variables only")
        print("Tip: copy .env.example -> .env and fill in your API keys")
except ImportError:
    print("python-dotenv not installed. Run: pip install python-dotenv")
    print("Falling back to manual parser (limited quote support)")
    import os
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ[k] = v
        print("Loaded .env (manual parser)")


# ── Thin layer thresholds — synthetic pairs auto-trigger below these ───────
SYNTHETIC_LAYER_THRESHOLDS = {
    "execution_context":    200,
    "remediation_learning": 500,
}


def step(label: str, fn, *args, **kwargs):
    """Run a pipeline step with timing and error isolation."""
    print(f"\n{'─'*60}")
    print(f"  ▶  {label}")
    print(f"{'─'*60}")
    t0 = time.time()
    try:
        fn(*args, **kwargs)
        elapsed = time.time() - t0
        print(f"  ✅ Done in {elapsed:.1f}s")
    except Exception as exc:
        elapsed = time.time() - t0
        print(f"  ❌ FAILED after {elapsed:.1f}s: {exc}")
        import traceback
        traceback.print_exc()


def count_layers(path: Path | None = None) -> dict:
    """Count training pairs by layer in the JSONL file."""
    import json
    target = path or TRAINING_PAIRS
    counts: dict[str, int] = {}
    if not target.exists():
        return counts
    with open(target, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                layer = rec.get("layer", "unknown")
                counts[layer] = counts.get(layer, 0) + 1
            except Exception:
                pass
    return counts


def should_run_synthetic() -> bool:
    """Return True if any layer is below its threshold."""
    if not TRAINING_PAIRS.exists():
        return False
    counts = count_layers()
    for layer, threshold in SYNTHETIC_LAYER_THRESHOLDS.items():
        actual = counts.get(layer, 0)
        if actual < threshold:
            print(f"  Thin layer: {layer} = {actual} examples (threshold: {threshold})")
            return True
    return False


def run_synthetic_pairs():
    """Import and run generate_synthetic_pairs.run()."""
    import importlib.util
    synthetic_path = Path(__file__).parent / "generate_synthetic_pairs.py"
    if not synthetic_path.exists():
        print("  generate_synthetic_pairs.py not found in project root — skipping")
        return
    spec = importlib.util.spec_from_file_location("generate_synthetic_pairs", synthetic_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.run()


def main():
    parser = argparse.ArgumentParser(description="Vulnerability dataset pipeline")
    parser.add_argument("--open-only",    action="store_true", help="Skip closed/auth sources")
    parser.add_argument("--from-build",   action="store_true", help="Skip crawling, rebuild dataset only")
    parser.add_argument("--correlate",    action="store_true", help="Re-run correlation step then rebuild")
    parser.add_argument("--synthetic",    action="store_true", help="Re-run synthetic pair generation only")
    parser.add_argument("--no-synthetic", action="store_true", help="Skip synthetic generation even if layers thin")
    parser.add_argument("--nvd-total",    type=int, default=10000, help="NVD records to fetch")
    args = parser.parse_args()

    # FIX: use Path.mkdir, not os.makedirs or string "data"
    DATA_DIR.mkdir(exist_ok=True)

    # ── --synthetic only ───────────────────────────────────────────────────
    if args.synthetic:
        print("\nRunning synthetic pair generation only...")
        step("Synthetic Training Pairs (thin layer boost)", run_synthetic_pairs)
        _print_summary(show_layer_counts=True)
        return

    # ── --correlate ────────────────────────────────────────────────────────
    if args.correlate:
        from data.build_correlations import run as run_correlations
        step("Vulnerability Correlation Graph", run_correlations)
        from build_cooccurrence_v2 import run as run_cooccurrence
        step("Vulnerability Co-occurrence Model", run_cooccurrence)
        from data.build_dataset import run as run_build
        step("Build Dataset (merge + training pairs)", run_build)
        if not args.no_synthetic and should_run_synthetic():
            step("Synthetic Training Pairs (thin layer boost)", run_synthetic_pairs)
        _print_summary(show_layer_counts=True)
        return

    # ── Full pipeline ──────────────────────────────────────────────────────
    if not args.from_build:
        from data.crawl_nvd import run as run_nvd
        step("NVD CVE Database", run_nvd, total=args.nvd_total)

        from data.crawl_epss import run as run_epss
        step("EPSS Exploit Scores", run_epss)

        from data.crawl_github import run as run_github
        step("GitHub Security Advisories", run_github)

        from data.crawl_blogs import run as run_blogs
        # FIX: pass out as a Path-derived string — consistent cross-platform
        step("Security Blogs (Exploit-DB / OWASP / Vulhub)", run_blogs,
             out=str(DATA_DIR / "raw_blogs.json"))

        from data.crawl_exploitdb import run as run_exploitdb
        step("Exploit-DB Bulk CSV", run_exploitdb)

        from data.crawl_cisa_kev import run as run_kev
        step("CISA Known Exploited Vulnerabilities", run_kev)

        from data.crawl_papers import run as run_papers
        step("Research Papers (arXiv + Semantic Scholar + OSV)", run_papers)

        from data.crawl_mitre_attack import run as run_mitre
        step("MITRE ATT&CK + CAPEC Correlation Data", run_mitre)

        from data.crawl_vendor_advisories import run as run_vendors
        step("Vendor Security Advisories (Cisco/RedHat/Ubuntu/Debian)", run_vendors)

        if not args.open_only:
            from data.crawl_closed_sources import run as run_closed
            step("Closed Sources (KEV/HackerOne/MSRC/Full Disclosure)", run_closed)

        from data.build_correlations import run as run_correlations
        step("Vulnerability Correlation Graph", run_correlations)

        from build_cooccurrence_v2 import run as run_cooccurrence
        step("Vulnerability Co-occurrence Model (P(B|A), P(B|not A))", run_cooccurrence)

    from data.build_dataset import run as run_build
    step("Build Dataset (merge + training pairs)", run_build)

    # ── Auto synthetic: runs only when layers are thin ─────────────────────
    if not args.no_synthetic:
        if should_run_synthetic():
            step("Synthetic Training Pairs (thin layer boost)", run_synthetic_pairs)
        else:
            print("\n  All layers above threshold — skipping synthetic generation")
    else:
        print("\n  Synthetic generation skipped (--no-synthetic flag)")

    _print_summary(show_layer_counts=True)


def _print_summary(show_layer_counts: bool = False):
    print(f"\n{'='*60}")
    print("  Pipeline complete!")
    print(f"{'='*60}")

    # FIX: all paths built via Path objects — no backslash literals
    outputs = {
        DATA_DIR / "raw_mitre_attack.json":      "ATT&CK + CAPEC data",
        DATA_DIR / "raw_vendor_advisories.json": "Cisco/RedHat/Ubuntu/Debian",
        DATA_DIR / "raw_correlations.json":      "CVE correlation graph",
        DATA_DIR / "raw_cooccurrence.json":      "P(B|A) co-occurrence model",
        DATA_DIR / "vuln_dataset.jsonl":         "full schema records",
        DATA_DIR / "training_pairs.jsonl":       "fine-tuning pairs",
    }
    print("  Outputs:")
    for path, desc in outputs.items():
        status = "OK" if path.exists() else "MISSING"
        print(f"    [{status}]  {str(path):<42} — {desc}")

    if show_layer_counts and TRAINING_PAIRS.exists():
        counts = count_layers()
        total  = sum(counts.values())
        print(f"\n  Training pairs by layer (total: {total:,}):")
        for layer, count in sorted(counts.items(), key=lambda x: -x[1]):
            threshold = SYNTHETIC_LAYER_THRESHOLDS.get(layer)
            flag = (
                f"  ⚠️  below threshold ({threshold})"
                if threshold and count < threshold
                else ""
            )
            print(f"    {layer:<38} {count:>7,}{flag}")

    print("\n  Next steps:")
    print("    python validate_dataset.py          — health check before training")
    print("    python training/finetuning.py       — start fine-tuning")
    print("\n  Quick re-runs:")
    print("    python run_pipeline.py --correlate   — redo correlation + build")
    print("    python run_pipeline.py --synthetic   — redo synthetic pairs only")
    print("    python run_pipeline.py --from-build  — redo build + synthetic only")


if __name__ == "__main__":
    main()