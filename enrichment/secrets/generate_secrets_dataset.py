import requests
import json

OUTPUT_FILE = "data/secrets_detection.jsonl"

# Correct RAW URL
GITLEAKS_RAW = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"

def build():
    response = requests.get(GITLEAKS_RAW)

    if response.status_code != 200:
        print("Failed to fetch Gitleaks config")
        return

    content = response.text.split("\n")

    records = []

    for line in content:
        line = line.strip()

        if line.startswith("id ="):
            rule_id = line.split("=")[1].strip().replace('"', '')

            records.append({
                "layer": "secrets_detection",
                "rule_id": rule_id,
                "description": "Secret detection rule from Gitleaks"
            })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} secrets rules")

if __name__ == "__main__":
    build()