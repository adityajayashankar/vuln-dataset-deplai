import requests
import json

OUTPUT_FILE = "data/iac_misconfiguration.jsonl"

BASE_API = "https://api.github.com/repos/bridgecrewio/checkov/contents/checkov/terraform/checks/resource"

def fetch_folder_contents(url):
    response = requests.get(url)
    return response.json()

def build_iac_dataset():
    records = []
    folders = fetch_folder_contents(BASE_API)

    for folder in folders:
        if folder["type"] == "dir":
            sub_items = fetch_folder_contents(folder["url"])

            for item in sub_items:
                if item["type"] == "file" and item["name"].endswith(".py"):
                    records.append({
                        "layer": "iac_misconfiguration",
                        "source": "checkov",
                        "resource_type": folder["name"],
                        "rule_file": item["name"],
                        "rule_path": item["path"]
                    })

    with open(OUTPUT_FILE, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    print(f"Generated {len(records)} IaC misconfiguration rules")

if __name__ == "__main__":
    build_iac_dataset()