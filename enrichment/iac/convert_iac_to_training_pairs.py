import json

INPUT_FILE = "data/iac_misconfiguration.jsonl"
OUTPUT_FILE = "data/iac_training_pairs.jsonl"

def infer_severity(rule_name):
    name = rule_name.lower()
    if "public" in name or "open" in name:
        return "HIGH"
    if "encryption" in name or "kms" in name:
        return "MEDIUM"
    return "LOW"

def build_training_pairs():
    records = []

    with open(INPUT_FILE) as f:
        for line in f:
            rule = json.loads(line)

            rule_name = rule["rule_file"].replace(".py", "")
            severity = infer_severity(rule_name)

            records.append({
                "layer": "iac_misconfiguration",
                "input": f"Terraform resource misconfiguration related to {rule_name}",
                "output": {
                    "finding": rule_name.upper(),
                    "severity": severity,
                    "fix": "Review Terraform configuration and apply secure defaults."
                }
            })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} IaC training pairs")

if __name__ == "__main__":
    build_training_pairs()