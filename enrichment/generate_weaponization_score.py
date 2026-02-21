import json

INPUT_FILE = "data/vuln_dataset.jsonl"
KEV_FILE = "data/cve_kev_enrichment.jsonl"
OUTPUT_FILE = "data/cve_weaponization_score.jsonl"

print("Loading KEV enrichment...")

kev_lookup = {}

with open(KEV_FILE, "r") as f:
    for line in f:
        record = json.loads(line)
        kev_lookup[record["cve_id"]] = record

print("Computing weaponization scores...")

results = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        cve_id = cve["cve_id"]

        # Base values
        try:
            cvss_score = float(cve.get("cvss_score", 0))
        except:
            cvss_score = 0

        try:
            epss_score = float(cve.get("epss_score", 0) or 0)
        except:
            epss_score = 0
        try:
            exploit_count = int(cve.get("exploit_count", 0) or 0)
        except:
            exploit_count = 0
        score = 0

        # KEV signal
        kev_data = kev_lookup.get(cve_id)
        if kev_data and kev_data["in_kev"]:
            score += 0.4

            if kev_data.get("ransomware_flag") == "Known":
                score += 0.3

        # EPSS signal
        if epss_score >= 0.5:
            score += 0.15

        # CVSS severity signal
        if cvss_score >= 8:
            score += 0.1

        # Exploit count signal
        if exploit_count > 0:
            score += 0.05

        # Normalize max to 1.0
        score = round(min(score, 1.0), 2)

        # Classification
        if score >= 0.75:
            level = "Critical"
        elif score >= 0.5:
            level = "High"
        elif score >= 0.25:
            level = "Medium"
        else:
            level = "Low"

        results.append({
            "cve_id": cve_id,
            "weaponization_score": score,
            "weaponization_level": level
        })

with open(OUTPUT_FILE, "w") as out:
    for record in results:
        out.write(json.dumps(record) + "\n")

print(f"Generated weaponization scores for {len(results)} CVEs.")