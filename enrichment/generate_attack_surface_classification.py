import json

INPUT_FILE = "data/vuln_dataset.jsonl"
OUTPUT_FILE = "data/cve_attack_surface_classification.jsonl"

print("Classifying CVEs by attack surface...")

def classify_attack_surface(description):
    description = description.lower()

    if any(word in description for word in ["sql injection", "xss", "http", "web", "apache", "nginx"]):
        return "Web-Facing"

    if any(word in description for word in ["remote attacker", "network", "port", "tcp", "udp"]):
        return "Network-Exposed"

    if any(word in description for word in ["local user", "privilege escalation", "local attacker"]):
        return "Local Privilege Escalation"

    if any(word in description for word in ["kernel", "linux kernel", "windows kernel"]):
        return "Kernel / OS"

    if any(word in description for word in ["npm", "pypi", "maven", "dependency", "library"]):
        return "Supply Chain"

    if any(word in description for word in ["cloud", "aws", "azure", "gcp"]):
        return "Cloud"

    if any(word in description for word in ["browser", "chrome", "firefox", "client-side"]):
        return "Client-Side"

    return "Other"

results = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        cve_id = cve["cve_id"]
        description = cve.get("description", "")

        surface = classify_attack_surface(description)

        results.append({
            "cve_id": cve_id,
            "attack_surface": surface
        })

with open(OUTPUT_FILE, "w") as out:
    for record in results:
        out.write(json.dumps(record) + "\n")

print(f"Generated attack surface classification for {len(results)} CVEs.")