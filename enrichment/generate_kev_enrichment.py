import requests
import json

INPUT_FILE = "data/vuln_dataset.jsonl"
OUTPUT_FILE = "data/cve_kev_enrichment.jsonl"

print("Fetching CISA KEV catalog...")

kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_data = requests.get(kev_url).json()

kev_cves = {}

for item in kev_data["vulnerabilities"]:
    kev_cves[item["cveID"]] = {
        "dateAdded": item["dateAdded"],
        "ransomware": item.get("knownRansomwareCampaignUse", "Unknown")
    }

print(f"Loaded {len(kev_cves)} KEV entries.")

enriched = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        cve_id = cve["cve_id"]

        # Get CVSS score from dataset (default 0 if missing)
        try:
            cvss_score = float(cve.get("cvss_score", 0))
        except:
            cvss_score = 0

        if cve_id in kev_cves:
            ransomware = kev_cves[cve_id]["ransomware"]

            # Priority Logic
            if ransomware == "Known":
                priority = "Critical"
            elif cvss_score >= 8:
                priority = "High"
            else:
                priority = "Medium"

            enriched.append({
                "cve_id": cve_id,
                "in_kev": True,
                "kev_date_added": kev_cves[cve_id]["dateAdded"],
                "ransomware_flag": ransomware,
                "known_exploited": True,
                "priority": priority,
                "source": "CISA KEV"
            })
        else:
            enriched.append({
                "cve_id": cve_id,
                "in_kev": False,
                "kev_date_added": None,
                "ransomware_flag": None,
                "known_exploited": False,
                "priority": "Low",
                "source": "CISA KEV"
            })

with open(OUTPUT_FILE, "w") as out:
    for record in enriched:
        out.write(json.dumps(record) + "\n")

print(f"Generated KEV enrichment with priority scoring for {len(enriched)} CVEs.")