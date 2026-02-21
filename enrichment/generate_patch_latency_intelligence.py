import json
from datetime import datetime

INPUT_FILE = "data/vuln_dataset.jsonl"
KEV_FILE = "data/cve_kev_enrichment.jsonl"
OUTPUT_FILE = "data/cve_patch_latency_intelligence.jsonl"

print("Loading KEV enrichment...")

kev_lookup = {}

with open(KEV_FILE, "r") as f:
    for line in f:
        record = json.loads(line)
        if record["in_kev"]:
            kev_lookup[record["cve_id"]] = record["kev_date_added"]

print("Computing patch latency intelligence...")

results = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        cve_id = cve["cve_id"]
        published_date_str = cve.get("published", None)

        latency_days = None
        exploitation_speed = "Not Exploited"

        if cve_id in kev_lookup and published_date_str:
            try:
                published_date = datetime.fromisoformat(published_date_str.replace("Z", ""))
                kev_date = datetime.fromisoformat(kev_lookup[cve_id])

                latency_days = (kev_date - published_date).days

                if latency_days <= 7:
                    exploitation_speed = "Rapid"
                elif latency_days <= 30:
                    exploitation_speed = "Fast"
                elif latency_days <= 90:
                    exploitation_speed = "Moderate"
                else:
                    exploitation_speed = "Slow"

            except:
                latency_days = None
                exploitation_speed = "Unknown"

        results.append({
            "cve_id": cve_id,
            "published_date": published_date_str,
            "kev_date_added": kev_lookup.get(cve_id),
            "days_to_known_exploitation": latency_days,
            "exploitation_speed": exploitation_speed
        })

with open(OUTPUT_FILE, "w") as out:
    for record in results:
        out.write(json.dumps(record) + "\n")

print(f"Generated patch latency intelligence for {len(results)} CVEs.")