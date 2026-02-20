"""
run_cooccurrence_pipeline.py  (FIXED v3 - subprocess approach)
Runs each step as a direct subprocess call — no importlib, no sys.path issues.
"""

import argparse
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = Path("data")


def separator(title):
    log.info("\n" + "─" * 60)
    log.info(f"  ▶  {title}")
    log.info("─" * 60)


def run_script(step_num, title, script_name, check_output=None, extra_args=None):
    separator(f"Step {step_num}: {title}")
    t0  = time.time()
    cmd = [sys.executable, script_name] + (extra_args or [])

    log.info(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)   # stream output live

    elapsed = time.time() - t0
    if result.returncode != 0:
        log.error(f"  ❌ Step {step_num} failed (exit code {result.returncode})")
        log.error(f"  Fix the error above, then resume with:")
        log.error(f"    python run_cooccurrence_pipeline.py --from-step {step_num}")
        return False

    log.info(f"  ✅ Done in {elapsed:.1f}s")
    if check_output and Path(check_output).exists():
        size = Path(check_output).stat().st_size
        log.info(f"  Output: {check_output}  ({size:,} bytes)")
    return True


def check_prerequisites():
    required = {
        "data/raw_cisa_kev.json":  "Run main pipeline first",
        "data/vuln_dataset.jsonl": "Run main pipeline first",
    }
    missing = [f"  ✗ {p}  →  {h}" for p, h in required.items() if not Path(p).exists()]
    if missing:
        log.error("Prerequisites missing:")
        for m in missing:
            log.error(m)
        return False

    # Check all required scripts exist
    scripts = [
        "collect_cwe_chains.py",
        "cluster_kev_campaigns.py",
        "build_cooccurrence_v2.py",
        "generate_cooccurrence_pairs.py",
        "stack_profiles.py",
    ]
    missing_scripts = [s for s in scripts if not Path(s).exists()]
    if missing_scripts:
        log.error("Missing scripts in project root:")
        for s in missing_scripts:
            log.error(f"  ✗ {s}")
        return False

    return True


def print_summary(pairs_target):
    log.info("\n" + "=" * 60)
    log.info("  Co-occurrence Pipeline Complete")
    log.info("=" * 60)

    training_file = DATA_DIR / "training_pairs.jsonl"
    if training_file.exists():
        layer_counts, type_counts, total = {}, {}, 0
        with open(training_file) as f:
            for line in f:
                try:
                    rec   = json.loads(line)
                    layer = rec.get("layer", "unknown")
                    ptype = rec.get("type", "")
                    layer_counts[layer] = layer_counts.get(layer, 0) + 1
                    if ptype:
                        type_counts[ptype] = type_counts.get(ptype, 0) + 1
                    total += 1
                except Exception:
                    pass

        log.info(f"\n  Total training pairs: {total:,}")
        log.info("\n  By layer:")
        for layer, count in sorted(layer_counts.items(), key=lambda x: -x[1]):
            flag = "  ⚠️  below 200" if count < 200 else ""
            log.info(f"    {layer:45s}  {count:,}{flag}")

        cooc = layer_counts.get("vulnerability_cooccurrence", 0)
        log.info(f"\n  vulnerability_cooccurrence: {cooc:,}")
        if cooc >= pairs_target * 0.8:
            log.info(f"  ✅ Target {pairs_target:,} achieved")
        else:
            log.warning(f"  ⚠️  Below target {pairs_target:,}")

        if type_counts:
            log.info("\n  Co-occurrence pair types:")
            for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
                log.info(f"    {t:35s}  {c:,}")

    cooc_v2 = DATA_DIR / "raw_cooccurrence_v2.json"
    if cooc_v2.exists():
        with open(cooc_v2) as f:
            stats = json.load(f).get("stats", {})
        log.info(f"\n  Co-occurrence model stats:")
        log.info(f"    Total pairs:    {stats.get('total_pairs', 0):,}")
        log.info(f"    Negative rules: {stats.get('negative_rules', 0):,}")
        log.info(f"    Stack profiles: {stats.get('stack_profiles', 0):,}")
        log.info("\n    By source:")
        for src, c in sorted(stats.get("by_source", {}).items(), key=lambda x: -x[1]):
            log.info(f"      {src:35s}  {c:,}")

    log.info("\n  Next: python validate_dataset.py")


def run_cooccurrence_pipeline(from_step=1, only_step=None, pairs_target=15000):
    if not check_prerequisites():
        sys.exit(1)

    steps = [
        (1, "CWE Relationship Chains",  "collect_cwe_chains.py",    "data/raw_cwe_chains.json",       None),
        (2, "KEV Campaign Clustering",  "cluster_kev_campaigns.py", "data/raw_kev_clusters.json",     None),
        (3, "Co-occurrence Model v2",   "build_cooccurrence_v2.py", "data/raw_cooccurrence_v2.json",  None),
        (4, "Generate Training Pairs",  "generate_cooccurrence_pairs.py",
            "data/training_pairs.jsonl", ["--count", str(pairs_target)]),
    ]

    t0 = time.time()
    for step_num, title, script, output, extra_args in steps:
        if only_step and step_num != only_step:
            continue
        if step_num < from_step:
            log.info(f"  Skipping Step {step_num}: {title}")
            continue

        ok = run_script(step_num, title, script, output, extra_args)
        if not ok:
            sys.exit(1)

    log.info(f"\n  Total elapsed: {time.time() - t0:.1f}s")
    print_summary(pairs_target)


def main():
    parser = argparse.ArgumentParser(description="Co-occurrence pipeline extension")
    parser.add_argument("--from-step", type=int, default=1, metavar="N",
                        help="Resume from step N (1-4)")
    parser.add_argument("--step",      type=int, default=None, metavar="N",
                        help="Run only step N")
    parser.add_argument("--pairs",     type=int, default=15000,
                        help="Target number of co-occurrence training pairs")
    args = parser.parse_args()

    run_cooccurrence_pipeline(
        from_step=args.from_step,
        only_step=args.step,
        pairs_target=args.pairs,
    )


if __name__ == "__main__":
    main()