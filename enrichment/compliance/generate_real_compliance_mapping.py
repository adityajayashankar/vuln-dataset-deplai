import json

INPUT_FILE = "data/vuln_dataset.jsonl"
OUTPUT_FILE = "data/compliance_mapping.jsonl"

def map_controls(cvss):
    if cvss >= 9:
        return ["PCI-DSS 6.3.3", "SOC2 CC7.1", "HIPAA 164.312"]
    if cvss >= 7:
        return ["SOC2 CC7.1"]
    return []

def build():
    records = []

    with open(INPUT_FILE) as f:
        for line in f:
            cve = json.loads(line)
            cvss = float(cve.get("cvss_score", 0) or 0)

            records.append({
                "cve_id": cve.get("cve_id"),
                "compliance_violations": map_controls(cvss)
            })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated compliance mapping")

if __name__ == "__main__":
    build()