import json
from attack_keywords import attack_keywords

INPUT_FILE = "data/vuln_dataset.jsonl"
OUTPUT_FILE = "data/cve_attack_mapping.jsonl"

mapped_records = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        description = cve["description"].lower()

        matched_techniques = []
        matched_tactics = []
        total_keyword_matches = 0

        for technique_id, data in attack_keywords.items():
            keywords = data["keywords"]
            tactic = data["tactic"]

            match_count = sum(1 for keyword in keywords if keyword in description)

            if match_count > 0:
                matched_techniques.append(technique_id)
                matched_tactics.append(tactic)
                total_keyword_matches += match_count

        if matched_techniques:
            # Confidence scoring
            if total_keyword_matches == 1:
                confidence = 0.6
            elif total_keyword_matches == 2:
                confidence = 0.8
            else:
                confidence = 0.95

            mapped_records.append({
                "cve_id": cve["cve_id"],
                "attack_techniques": matched_techniques,
                "tactics": list(set(matched_tactics)),
                "confidence": confidence,
                "mapping_method": "keyword_rule_v2"
            })

with open(OUTPUT_FILE, "w") as out:
    for record in mapped_records:
        out.write(json.dumps(record) + "\n")

print(f"Generated {len(mapped_records)} enriched CVE → ATT&CK mappings.")