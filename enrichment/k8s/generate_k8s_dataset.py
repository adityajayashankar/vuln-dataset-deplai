import requests
import json

OUTPUT_FILE = "data/k8s_container_security.jsonl"

KUBE_BENCH = "https://api.github.com/repos/aquasecurity/kube-bench/contents/cfg"

def fetch():
    response = requests.get(KUBE_BENCH)
    return response.json()

def build():
    data = fetch()
    records = []

    for item in data:
        records.append({
            "layer": "k8s_container_security",
            "file": item.get("name"),
            "path": item.get("path")
        })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} Kubernetes records")

if __name__ == "__main__":
    build()