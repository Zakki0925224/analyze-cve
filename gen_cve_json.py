import json
import os
from cpe import CPE

nvdcve_dir = "nist-nvdcve"
export_file = "cve-list.json"
nvdcve_files = os.listdir(nvdcve_dir)
nvdcve_files.sort()
objs = []
cve_items = []

for file in nvdcve_files:
    with open(f"./{nvdcve_dir}/{file}", "r") as f:
        objs.append(json.load(f))
    print(f"loaded {file}")

cve_items_len = sum(len(x["CVE_Items"]) for x in objs)

for obj in objs:
    for item in obj["CVE_Items"]:
        _cpes = [x["cpe23Uri"] for node in item["configurations"]["nodes"] for x in node["cpe_match"]]
        products = []
        vendors = []

        for cpe in _cpes:
            cpe = CPE(cpe)
            products += cpe.get_product()
            vendors += cpe.get_vendor()

        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        cwe_id = [x["value"] for x in [y for sublist in [description['description'] for description in item["cve"]["problemtype"]["problemtype_data"]] for y in sublist]]
        descriptions = [x["value"] for x in item["cve"]["description"]["description_data"]]
        published_date = item["publishedDate"]
        last_modified_date = item["lastModifiedDate"]


        cvssv2 = {}
        cvssv2_base_metrics = {}
        try:
            _base_metricv2 = item["impact"]["baseMetricV2"]
            cvssv2_base_metrics["access_vector"] = _base_metricv2["cvssV2"]["accessVector"]
            cvssv2_base_metrics["access_complexity"] = _base_metricv2["cvssV2"]["accessComplexity"]
            cvssv2_base_metrics["authentication"] = _base_metricv2["cvssV2"]["authentication"]
            cvssv2_base_metrics["confidentiality_impact"] = _base_metricv2["cvssV2"]["confidentialityImpact"]
            cvssv2_base_metrics["integrity_impact"] = _base_metricv2["cvssV2"]["integrityImpact"]
            cvssv2_base_metrics["availability_impact"] = _base_metricv2["cvssV2"]["availabilityImpact"]
            cvssv2_base_metrics["base_score"] = _base_metricv2["cvssV2"]["baseScore"]
            cvssv2["base_metrics"] = cvssv2_base_metrics
            cvssv2["severity"] = _base_metricv2["severity"]
            cvssv2["exploitability_score"] = _base_metricv2["exploitabilityScore"]
            cvssv2["impact_score"] = _base_metricv2["impactScore"]

        except:
            cvssv2_base_metrics["access_vector"] = ""
            cvssv2_base_metrics["access_complexity"] = ""
            cvssv2_base_metrics["authentication"] = ""
            cvssv2_base_metrics["confidentiality_impact"] = ""
            cvssv2_base_metrics["integrity_impact"] = ""
            cvssv2_base_metrics["availability_impact"] = ""
            cvssv2_base_metrics["base_score"] = -1
            cvssv2["base_metrics"] = cvssv2_base_metrics
            cvssv2["severity"] = ""
            cvssv2["exploitability_score"] = -1
            cvssv2["impact_score"] = -1

        # remove duplicates
        products = list(set(products))
        vendors = list(set(vendors))

        cve = {}
        cve["cve_id"] = cve_id
        cve["cwe_id"] = cwe_id
        cve["descriptions"] = descriptions
        cve["products"] = products
        cve["vendors"] = vendors
        cve["published_date"] = published_date
        cve["last_modified_date"] = last_modified_date
        cve["cvssv2"] = cvssv2

        cve_items.append(cve)
        cve_items_len -= 1
        print(f"remaing: {cve_items_len}")

with open(f"./{export_file}", "w") as f:
    f.write(json.dumps(cve_items))
    print(f"generated ./{export_file}")