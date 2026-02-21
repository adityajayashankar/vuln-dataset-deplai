import json

INPUT_FILE = "data/k8s_container_security.jsonl"
OUTPUT_FILE = "data/k8s_training_pairs.jsonl"

def infer_severity(name):
    name = name.lower()
    if "privileged" in name or "root" in name:
        return "HIGH"
    if "capabilities" in name:
        return "MEDIUM"
    return "LOW"

def build():
    records = []

    with open(INPUT_FILE) as f:
        for line in f:
            item = json.loads(line)
            rule_name = item.get("file", "unknown")

            severity = infer_severity(rule_name)

            records.append({
                "layer": "k8s_container_security",
                "input": f"Kubernetes misconfiguration related to {rule_name}",
                "output": {
                    "finding": rule_name.upper(),
                    "severity": severity,
                    "fix": "Review Kubernetes configuration and apply CIS benchmark recommendations."
                }
            })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} K8s training pairs")

if __name__ == "__main__":
    build()