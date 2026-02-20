#!/usr/bin/env python3
"""
run_pipeline.py  —  DeplAI Dataset Pipeline (Master Orchestrator)
=================================================================
Runs every step from raw data collection through to final training dataset.

Phases:
  1. COLLECT    — Crawl all data sources (NVD, EPSS, KEV, GitHub, Blogs, …)
  2. CORRELATE  — Build CVE correlation graph + co-occurrence model
  3. BUILD      — Merge everything → vuln_dataset.jsonl + training_pairs.jsonl
  4. VALIDATE   — Health-check the output before training

Usage:
    python run_pipeline.py                  # full pipeline
    python run_pipeline.py --skip-crawl     # use cached raw_*.json, re-run correlate+build
    python run_pipeline.py --from-build     # skip crawl+correlate, only rebuild dataset
    python run_pipeline.py --only collect   # run only collection phase
    python run_pipeline.py --only build     # run only build phase
    python run_pipeline.py --open-only      # skip closed/auth-required sources
    python run_pipeline.py --force          # re-run steps even if output exists
    python run_pipeline.py --dry-run        # show plan without executing
    python run_pipeline.py --nvd-total 50000

Pipeline Order (18 steps):

  COLLECT:
    1.  NVD               → data/raw_nvd.json
    2.  EPSS              → data/raw_epss.json
    3.  GitHub            → data/raw_github.json
    4.  Blogs             → data/raw_blogs.json
    5.  Exploit-DB        → data/raw_exploitdb.json
    6.  CISA KEV          → data/raw_cisa_kev.json
    7.  Papers            → data/raw_papers.json
    8.  MITRE ATT&CK      → data/raw_mitre_attack.json
    9.  Vendor Advisories → data/raw_vendor_advisories.json
   10.  Closed Sources    → data/raw_closed.json

  CORRELATE:
   11.  Correlation Graph → data/raw_correlations.json
   12.  CWE Chains        → data/raw_cwe_chains.json
   13.  KEV Clusters      → data/raw_kev_clusters.json
   14.  Co-occurrence     → data/raw_cooccurrence.json

  BUILD:
   15.  Build Dataset     → data/vuln_dataset.jsonl + data/training_pairs.jsonl
   16.  Co-occ Pairs      → appended to data/training_pairs.jsonl
   17.  Synthetic Pairs   → appended to data/training_pairs.jsonl (only if thin)

  VALIDATE:
   18.  Quality Check     → prints validation report
"""

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# PATHS
# ──────────────────────────────────────────────────────────────────────────────

ROOT          = Path(__file__).parent.resolve()
DATA_DIR      = ROOT / "data"
PYTHON        = sys.executable
SOURCES_YAML  = DATA_DIR / "sources.yaml"

# Ensure data/ directory and sys.path
DATA_DIR.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(DATA_DIR))


# ──────────────────────────────────────────────────────────────────────────────
# LOAD .env BEFORE any imports that need API keys
# ──────────────────────────────────────────────────────────────────────────────

def _load_env():
    env_path = ROOT / ".env"
    if not env_path.exists():
        print("  No .env found — using shell environment variables only")
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(dotenv_path=env_path, override=True)
        print("  Loaded .env (python-dotenv)")
    except ImportError:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ[k.strip()] = v.strip().strip('"').strip("'")
        print("  Loaded .env (manual parser)")

_load_env()


# ──────────────────────────────────────────────────────────────────────────────
# COLOURS
# ──────────────────────────────────────────────────────────────────────────────

class C:
    H  = "\033[95m"   # header/magenta
    B  = "\033[94m"   # blue
    G  = "\033[92m"   # green
    Y  = "\033[93m"   # yellow
    R  = "\033[91m"   # red
    BD = "\033[1m"    # bold
    DM = "\033[2m"    # dim
    _  = "\033[0m"    # reset


# ──────────────────────────────────────────────────────────────────────────────
# PIPELINE DEFINITION  (ordered list of every step)
# ──────────────────────────────────────────────────────────────────────────────

STEPS = [
    # ═════════════════════════════════════════════════════════════════════
    #  PHASE 1: COLLECT
    # ═════════════════════════════════════════════════════════════════════
    {
        "step": 1,  "phase": "collect",
        "name":  "NVD (National Vulnerability Database)",
        "import_": "data.crawl_nvd",  "fn": "run",
        "output": [DATA_DIR / "raw_nvd.json"],
        "slow": True,
    },
    {
        "step": 2,  "phase": "collect",
        "name":  "EPSS Exploitation Probability Scores",
        "import_": "data.crawl_epss",  "fn": "run",
        "output": [DATA_DIR / "raw_epss.json"],
        "slow": False,
    },
    {
        "step": 3,  "phase": "collect",
        "name":  "GitHub Security Advisories",
        "import_": "data.crawl_github",  "fn": "run",
        "output": [DATA_DIR / "raw_github.json"],
        "slow": True,
    },
    {
        "step": 4,  "phase": "collect",
        "name":  "Security Blogs (Agentic LLM + Tavily + crawl4ai)",
        "import_": "data.crawl_blogs",  "fn": "run",
        "kwargs_fn": lambda args: {
            "config_path": SOURCES_YAML,
            "out_override": str(DATA_DIR / "raw_blogs.json"),
        },
        "output": [DATA_DIR / "raw_blogs.json"],
        "slow": True,
    },
    {
        "step": 5,  "phase": "collect",
        "name":  "Exploit-DB Bulk CVE → Exploit Mapping",
        "import_": "data.crawl_exploitdb",  "fn": "run",
        "output": [DATA_DIR / "raw_exploitdb.json"],
        "slow": True,
    },
    {
        "step": 6,  "phase": "collect",
        "name":  "CISA KEV (Known Exploited Vulnerabilities)",
        "import_": "data.crawl_cisa_kev",  "fn": "run",
        "output": [DATA_DIR / "raw_cisa_kev.json"],
        "slow": False,
    },
    {
        "step": 7,  "phase": "collect",
        "name":  "Research Papers (Semantic Scholar + arXiv)",
        "import_": "data.crawl_papers",  "fn": "run",
        "output": [DATA_DIR / "raw_papers.json"],
        "slow": True,
    },
    {
        "step": 8,  "phase": "collect",
        "name":  "MITRE ATT&CK + CAPEC Correlation Data",
        "import_": "data.crawl_mitre_attack",  "fn": "run",
        "output": [DATA_DIR / "raw_mitre_attack.json"],
        "slow": False,
    },
    {
        "step": 9,  "phase": "collect",
        "name":  "Vendor Advisories (Cisco / Red Hat / Ubuntu / Debian)",
        "import_": "data.crawl_vendor_advisories",  "fn": "run",
        "output": [DATA_DIR / "raw_vendor_advisories.json"],
        "slow": True,
    },
    {
        "step": 10, "phase": "collect",
        "name":  "Closed Sources (HackerOne / MSRC / Full Disclosure)",
        "import_": "data.crawl_closed_sources",  "fn": "run",
        "output": [DATA_DIR / "raw_closed.json"],
        "slow": True,
        "closed": True,
    },

    # ═════════════════════════════════════════════════════════════════════
    #  PHASE 2: CORRELATE
    # ═════════════════════════════════════════════════════════════════════
    {
        "step": 11, "phase": "correlate",
        "name":  "CVE Correlation Graph",
        "import_": "data.build_correlations",  "fn": "run",
        "output": [DATA_DIR / "raw_correlations.json"],
        "slow": False,
    },
    {
        "step": 12, "phase": "correlate",
        "name":  "CWE Exploit Chain Collection",
        "import_": "collect_cwe_chains",  "fn": "main",
        "output": [DATA_DIR / "raw_cwe_chains.json"],
        "slow": False,
        "optional": True,
    },
    {
        "step": 13, "phase": "correlate",
        "name":  "KEV Campaign Clustering",
        "import_": "cluster_kev_campaigns",  "fn": "main",
        "output": [DATA_DIR / "raw_kev_clusters.json"],
        "slow": False,
        "optional": True,
    },
    {
        "step": 14, "phase": "correlate",
        "name":  "Co-occurrence Model (P(B|A), lift, profiles)",
        "import_": "build_cooccurrence_v2",  "fn": "main",
        "output": [DATA_DIR / "raw_cooccurrence_v2.json",
                   DATA_DIR / "raw_cooccurrence.json"],
        "slow": False,
    },

    # ═════════════════════════════════════════════════════════════════════
    #  PHASE 3: BUILD
    # ═════════════════════════════════════════════════════════════════════
    {
        "step": 15, "phase": "build",
        "name":  "Build Dataset (vuln_dataset.jsonl + training_pairs.jsonl)",
        "import_": "data.build_dataset",  "fn": "run",
        "output": [DATA_DIR / "vuln_dataset.jsonl",
                   DATA_DIR / "training_pairs.jsonl"],
        "slow": False,
        "always_run": True,   # always rebuild even if output exists
    },
    {
        "step": 16, "phase": "build",
        "name":  "Co-occurrence Training Pairs (append)",
        "import_": "generate_cooccurrence_pairs",  "fn": "main",
        "output": [DATA_DIR / "training_pairs.jsonl"],
        "slow": False,
        "optional": True,
        "always_run": True,
    },
    {
        "step": 17, "phase": "build",
        "name":  "Synthetic Pairs (thin-layer boost — if needed)",
        "import_": "generate_synthetic_pairs",  "fn": "run",
        "output": [DATA_DIR / "training_pairs.jsonl"],
        "slow": False,
        "conditional": True,
    },

    # ═════════════════════════════════════════════════════════════════════
    #  PHASE 4: VALIDATE
    # ═════════════════════════════════════════════════════════════════════
    {
        "step": 18, "phase": "validate",
        "name":  "Validate Dataset Quality",
        "import_": "validate_dataset",  "fn": "main",
        "output": [],
        "slow": False,
        "optional": True,
        "always_run": True,
    },
]

TOTAL_STEPS = len(STEPS)


# ──────────────────────────────────────────────────────────────────────────────
# THIN-LAYER DETECTION  (for conditional synthetic step)
# ──────────────────────────────────────────────────────────────────────────────

SYNTHETIC_LAYER_THRESHOLDS = {
    "execution_context":    200,
    "remediation_learning": 500,
}

def _layers_are_thin() -> bool:
    """Check if any training layer is below its minimum threshold."""
    tp = DATA_DIR / "training_pairs.jsonl"
    if not tp.exists():
        return False
    counts: dict[str, int] = {}
    with open(tp, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                layer = json.loads(line).get("layer", "unknown")
                counts[layer] = counts.get(layer, 0) + 1
            except Exception:
                pass
    for layer, threshold in SYNTHETIC_LAYER_THRESHOLDS.items():
        actual = counts.get(layer, 0)
        if actual < threshold:
            print(f"    Thin layer: {layer} = {actual} examples (threshold: {threshold})")
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# FILE STATS HELPER
# ──────────────────────────────────────────────────────────────────────────────

def _file_stats(path: Path) -> str:
    """Return human-readable size + record count for a data file."""
    if not path.exists():
        return "not found"
    size = path.stat().st_size
    if   size < 1024:        s = f"{size} B"
    elif size < 1024 * 1024: s = f"{size / 1024:.1f} KB"
    else:                    s = f"{size / (1024 * 1024):.1f} MB"

    count = ""
    try:
        if path.suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                count = f", {len(data):,} records"
            elif isinstance(data, dict):
                for key in ("cooccurrence_pairs", "results", "data", "records",
                            "pairs", "training_pairs", "vulnerabilities"):
                    if key in data and isinstance(data[key], list):
                        count = f", {len(data[key]):,} {key}"
                        break
                if not count:
                    count = f", {len(data)} top-level keys"
        elif path.suffix == ".jsonl":
            n = sum(1 for line in open(path, encoding="utf-8") if line.strip())
            count = f", {n:,} records"
    except Exception:
        pass
    return f"{s}{count}"


# ──────────────────────────────────────────────────────────────────────────────
# STEP RUNNER
# ──────────────────────────────────────────────────────────────────────────────

def _run_step(step_def: dict, args) -> dict:
    """Import the module, call the function, return result dict."""
    result = {
        "step":    step_def["step"],
        "name":    step_def["name"],
        "phase":   step_def["phase"],
        "status":  "pending",
        "elapsed": 0.0,
        "stats":   "",
    }

    # Conditional step (synthetic) — only runs if layers are thin
    if step_def.get("conditional"):
        if not _layers_are_thin():
            print(f"    All layers above threshold — skipping")
            result["status"] = "skipped"
            return result

    # Dry-run mode
    if args.dry_run:
        outputs = step_def.get("output", [])
        cached = all(p.exists() and p.stat().st_size > 100 for p in outputs) if outputs else False
        result["status"] = "cached" if cached else "would-run"
        return result

    t0 = time.time()
    try:
        import importlib
        mod = importlib.import_module(step_def["import_"])
        fn  = getattr(mod, step_def.get("fn", "run"))

        # Build kwargs
        kwargs = {}
        if "kwargs_fn" in step_def:
            kwargs = step_def["kwargs_fn"](args)
        elif step_def["step"] == 1:
            kwargs = {"total": args.nvd_total}

        # Temporarily clear sys.argv so sub-scripts' argparse doesn't
        # choke on run_pipeline.py's flags (e.g. --from-build)
        saved_argv = sys.argv
        sys.argv = [step_def["import_"]]
        try:
            fn(**kwargs)
        finally:
            sys.argv = saved_argv

        result["elapsed"] = time.time() - t0
        result["status"]  = "success"

        # Collect output file stats
        stats_parts = []
        for p in step_def.get("output", []):
            if p.exists():
                stats_parts.append(f"{p.name}: {_file_stats(p)}")
        result["stats"] = " | ".join(stats_parts)

    except Exception as exc:
        result["elapsed"] = time.time() - t0
        result["status"]  = "failed"
        result["error"]   = str(exc)
        print(f"\n    {C.R}ERROR: {exc}{C._}")
        traceback.print_exc()

    return result


# ──────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _banner():
    print(f"""{C.BD}{C.B}
╔═══════════════════════════════════════════════════════════════╗
║        DeplAI Dataset Pipeline  —  Master Orchestrator       ║
╠═══════════════════════════════════════════════════════════════╣
║  Phase 1: COLLECT    (10 data sources)                       ║
║  Phase 2: CORRELATE  (correlation graph + co-occurrence)     ║
║  Phase 3: BUILD      (dataset + training pairs)              ║
║  Phase 4: VALIDATE   (quality checks)                        ║
╚═══════════════════════════════════════════════════════════════╝{C._}

  {C.DM}Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Python  : {sys.executable}
  Root    : {ROOT}{C._}
""")


def _print_phase_header(phase: str):
    color = {"collect": C.B, "correlate": C.Y, "build": C.G, "validate": C.H}
    c = color.get(phase, C.B)
    print(f"\n{c}{C.BD}{'═' * 64}")
    print(f"  PHASE: {phase.upper()}")
    print(f"{'═' * 64}{C._}")


def _print_step_header(step_def: dict):
    print(f"\n  {C.BD}[{step_def['step']:2d}/{TOTAL_STEPS}]{C._}  {step_def['name']}")
    print(f"  {C.DM}{'─' * 56}{C._}")


def _print_summary(results: list[dict]):
    print(f"\n\n{C.BD}{C.G}{'═' * 64}")
    print(f"  PIPELINE SUMMARY")
    print(f"{'═' * 64}{C._}\n")

    total_time = 0.0
    passed = failed = skipped = 0

    # Group by phase
    phase_groups: dict[str, list] = {}
    for r in results:
        phase_groups.setdefault(r["phase"], []).append(r)

    for phase in ("collect", "correlate", "build", "validate"):
        group = phase_groups.get(phase, [])
        if not group:
            continue
        color = {"collect": C.B, "correlate": C.Y, "build": C.G, "validate": C.H}.get(phase, "")
        print(f"  {color}{C.BD}{phase.upper()}{C._}")

        for r in group:
            total_time += r["elapsed"]
            if r["status"] == "success":
                icon = f"{C.G}✔{C._}"; passed += 1
            elif r["status"] in ("skipped", "cached", "would-run"):
                icon = f"{C.Y}⊘{C._}"; skipped += 1
            else:
                icon = f"{C.R}✗{C._}"; failed += 1

            t = f"{r['elapsed']:.1f}s" if r["elapsed"] > 0 else ""
            print(f"    {icon}  {r['step']:2d}. {r['name']:<48s} {t}")
            if r.get("stats"):
                print(f"         {C.DM}{r['stats']}{C._}")
        print()

    print(f"  {'─' * 56}")
    print(f"  Total time : {total_time:.1f}s ({total_time / 60:.1f} min)")
    print(f"  {C.G}Passed: {passed}{C._}   {C.R}Failed: {failed}{C._}   {C.Y}Skipped: {skipped}{C._}")

    # ── Final dataset stats ──────────────────────────────────────────
    ds = DATA_DIR / "vuln_dataset.jsonl"
    tp = DATA_DIR / "training_pairs.jsonl"
    if ds.exists() and tp.exists():
        print(f"\n  {C.G}{C.BD}Final Output:{C._}")
        print(f"    vuln_dataset.jsonl    {_file_stats(ds)}")
        print(f"    training_pairs.jsonl  {_file_stats(tp)}")

        # Layer breakdown
        counts: dict[str, int] = {}
        try:
            with open(tp, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        layer = json.loads(line).get("layer", "unknown")
                        counts[layer] = counts.get(layer, 0) + 1
                    except Exception:
                        pass
        except Exception:
            pass

        if counts:
            total_pairs = sum(counts.values())
            print(f"\n  Training pairs by layer (total: {total_pairs:,}):")
            for layer, count in sorted(counts.items(), key=lambda x: -x[1]):
                thresh = SYNTHETIC_LAYER_THRESHOLDS.get(layer)
                flag = f"  {C.Y}⚠ below {thresh}{C._}" if thresh and count < thresh else ""
                print(f"    {layer:<40s} {count:>8,}{flag}")

    print(f"\n  {C.BD}Next steps:{C._}")
    print(f"    python training/finetuning.py         — start fine-tuning")
    print(f"\n  {C.BD}Quick re-runs:{C._}")
    print(f"    python run_pipeline.py --from-build    — rebuild dataset only")
    print(f"    python run_pipeline.py --skip-crawl    — re-correlate + rebuild")
    print(f"    python run_pipeline.py --only build    — just build phase")
    print(f"    python run_pipeline.py --force         — re-run everything")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="DeplAI Dataset Pipeline — Collection → Correlation → Build → Validate",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--skip-crawl",  action="store_true",
                        help="Skip collection phase (use cached raw_*.json)")
    parser.add_argument("--from-build",  action="store_true",
                        help="Skip collect + correlate, only rebuild dataset")
    parser.add_argument("--only",        choices=["collect", "correlate", "build", "validate"],
                        help="Run only one specific phase")
    parser.add_argument("--from-step",   type=int, default=1,
                        help="Resume from step N (1-18)")
    parser.add_argument("--open-only",   action="store_true",
                        help="Skip closed/auth-required sources (step 10)")
    parser.add_argument("--force",       action="store_true",
                        help="Re-run all steps even if output exists")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Show plan without executing anything")
    parser.add_argument("--continue-on-error", action="store_true",
                        help="Keep pipeline running even if a step fails")
    parser.add_argument("--no-synthetic", action="store_true",
                        help="Skip synthetic pair generation")
    parser.add_argument("--no-validate", action="store_true",
                        help="Skip validation step")
    parser.add_argument("--nvd-total",   type=int, default=10_000,
                        help="NVD CVE records to fetch (default: 10,000)")
    args = parser.parse_args()

    _banner()

    # ── Pre-flight warnings ──────────────────────────────────────────
    if not SOURCES_YAML.exists():
        print(f"  {C.Y}⚠ Missing {SOURCES_YAML}{C._}")
    if not (ROOT / ".env").exists():
        print(f"  {C.Y}⚠ No .env file — API keys may be missing{C._}")
    print()

    # ── Determine which phases to skip ───────────────────────────────
    skip_phases: set[str] = set()
    if args.from_build:
        skip_phases = {"collect", "correlate"}
    elif args.skip_crawl:
        skip_phases = {"collect"}
    if args.no_validate:
        skip_phases.add("validate")

    # ── Run pipeline ─────────────────────────────────────────────────
    results:    list[dict] = []
    last_phase: str | None = None

    for step_def in STEPS:
        snum  = step_def["step"]
        phase = step_def["phase"]

        # ── Skip checks ─────────────────────────────────────────
        skip_reason = None

        if args.only and phase != args.only:
            skip_reason = f"--only {args.only}"
        elif snum < args.from_step:
            skip_reason = f"--from-step {args.from_step}"
        elif phase in skip_phases:
            skip_reason = f"phase skipped"
        elif args.open_only and step_def.get("closed"):
            skip_reason = "--open-only"
        elif args.no_synthetic and step_def.get("conditional"):
            skip_reason = "--no-synthetic"

        if skip_reason:
            results.append({
                "step": snum, "name": step_def["name"],
                "phase": phase, "status": "skipped", "elapsed": 0.0, "stats": "",
            })
            continue

        # Auto-skip if output exists (unless --force or always_run)
        if not args.force and not args.dry_run and not step_def.get("always_run"):
            outputs = step_def.get("output", [])
            if outputs and all(p.exists() and p.stat().st_size > 100 for p in outputs):
                stats = " | ".join(f"{p.name}: {_file_stats(p)}" for p in outputs)
                print(f"  {C.Y}⊘ [{snum:2d}] Skipping {step_def['name']}{C._}")
                print(f"         {C.DM}(output exists: {stats}){C._}")
                results.append({
                    "step": snum, "name": step_def["name"],
                    "phase": phase, "status": "skipped", "elapsed": 0.0, "stats": stats,
                })
                continue

        # ── Phase header (once per phase) ────────────────────────
        if phase != last_phase:
            _print_phase_header(phase)
            last_phase = phase

        _print_step_header(step_def)

        # ── Execute ──────────────────────────────────────────────
        result = _run_step(step_def, args)
        results.append(result)

        if result["status"] == "success":
            print(f"  {C.G}✔ Done in {result['elapsed']:.1f}s{C._}")
            if result["stats"]:
                print(f"    {C.DM}{result['stats']}{C._}")

        elif result["status"] == "failed":
            print(f"  {C.R}✗ Failed after {result['elapsed']:.1f}s{C._}")
            if not args.continue_on_error and not step_def.get("optional"):
                print(f"\n  {C.R}Pipeline stopped at step {snum}.")
                print(f"  Use --continue-on-error to keep going.{C._}")
                break
            if step_def.get("optional"):
                print(f"    {C.Y}(optional step — continuing){C._}")

        elif result["status"] in ("skipped", "cached", "would-run"):
            print(f"  {C.Y}⊘ {result['status']}{C._}")

    _print_summary(results)


if __name__ == "__main__":
    main()
