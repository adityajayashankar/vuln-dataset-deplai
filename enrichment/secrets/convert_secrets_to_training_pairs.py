import json

INPUT_FILE = "data/secrets_detection.jsonl"
OUTPUT_FILE = "data/secrets_training_pairs.jsonl"

def build():
    records = []

    with open(INPUT_FILE) as f:
        for line in f:
            rule = json.loads(line)

            records.append({
                "layer": "secrets_detection",
                "input": f"Detected secret pattern: {rule['rule_id']}",
                "output": {
                    "secret_type": rule["rule_id"],
                    "action": "BLOCK_DEPLOYMENT",
                    "remediation": "Move secrets to environment variables or secret manager."
                }
            })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} secrets training pairs")

if __name__ == "__main__":
    build()