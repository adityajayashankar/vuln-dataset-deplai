import requests
import json
import zipfile
import io
import xml.etree.ElementTree as ET

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

INPUT_FILE = "data/vuln_dataset.jsonl"
OUTPUT_FILE = "data/cve_cwe_intelligence.jsonl"

print("Downloading CWE catalog ZIP...")

response = requests.get(CWE_ZIP_URL)

zip_file = zipfile.ZipFile(io.BytesIO(response.content))
xml_filename = zip_file.namelist()[0]
xml_data = zip_file.read(xml_filename)

print("Parsing CWE XML...")

root = ET.fromstring(xml_data)

# Extract namespace dynamically
namespace = root.tag.split("}")[0].strip("{")
ns = {"cwe": namespace}

cwe_lookup = {}

for weakness in root.findall(".//cwe:Weakness", ns):
    cwe_id = weakness.attrib.get("ID")
    name = weakness.attrib.get("Name")
    abstraction = weakness.attrib.get("Abstraction")

    description_elem = weakness.find("cwe:Description", ns)
    description = description_elem.text if description_elem is not None else ""

    likelihood_elem = weakness.find("cwe:Likelihood_Of_Exploit", ns)
    likelihood = likelihood_elem.text if likelihood_elem is not None else "Unknown"

    consequences = []
    for consequence in weakness.findall(".//cwe:Scope", ns):
        if consequence.text:
            consequences.append(consequence.text)

    cwe_lookup[f"CWE-{cwe_id}"] = {
        "weakness_name": name,
        "abstraction_level": abstraction,
        "description": description,
        "likelihood_of_exploit": likelihood,
        "impact_scopes": list(set(consequences))
    }

print(f"Loaded {len(cwe_lookup)} CWE definitions.")

print("Enriching CVEs with CWE intelligence...")

results = []

with open(INPUT_FILE, "r") as f:
    for line in f:
        cve = json.loads(line)
        cve_id = cve["cve_id"]
        cwe_id = cve.get("cwe_id", "").strip()

        if cwe_id in cwe_lookup:
            cwe_data = cwe_lookup[cwe_id]

            results.append({
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "weakness_name": cwe_data["weakness_name"],
                "abstraction_level": cwe_data["abstraction_level"],
                "likelihood_of_exploit": cwe_data["likelihood_of_exploit"],
                "impact_scopes": cwe_data["impact_scopes"]
            })
        else:
            results.append({
                "cve_id": cve_id,
                "cwe_id": cwe_id if cwe_id else None,
                "weakness_name": None,
                "abstraction_level": None,
                "likelihood_of_exploit": None,
                "impact_scopes": []
            })

with open(OUTPUT_FILE, "w") as out:
    for record in results:
        out.write(json.dumps(record) + "\n")

print(f"Generated CWE intelligence for {len(results)} CVEs.")