import json
from pathlib import Path

# ALL your training pair files
ALL_PAIR_FILES = [
    "data/training_pairs.jsonl",
    "data/iac_training_pairs.jsonl",
    "data/k8s_training_pairs.jsonl",
    "data/secrets_training_pairs.jsonl",
    "data/compliance_mapping.jsonl",
    "data/deployment_feedback.jsonl",
    "data/cve_attack_mapping.jsonl",
    "data/cve_attack_surface_classification.jsonl",
    "data/cve_cwe_intelligence.jsonl",
    "data/cve_kev_enrichment.jsonl",
    "data/cve_patch_latency_intelligence.jsonl",
    "data/cve_weaponization_score.jsonl",
]

OUTPUT = "data/all_training_pairs.jsonl"

all_records = []
for filepath in ALL_PAIR_FILES:
    p = Path(filepath)
    if not p.exists():
        print(f"  ⚠️  MISSING: {filepath}")
        continue
    count = 0
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    record = json.loads(line)
                    # Ensure every record has a layer field
                    if "layer" not in record:
                        record["layer"] = p.stem  # use filename as layer name
                    all_records.append(record)
                    count += 1
                except json.JSONDecodeError:
                    continue
    print(f"  ✅ {filepath:<45} → {count:,} pairs")

print(f"\n  Total merged: {len(all_records):,} pairs")

with open(OUTPUT, "w", encoding="utf-8") as f:
    for record in all_records:
        f.write(json.dumps(record) + "\n")

print(f"  Saved → {OUTPUT}")