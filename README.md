## Data source

- [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds) - JSON Feeds (`./nist-nvdcve/nvdcve-1.1-\*.json`)

## Usage

- Download JSON Feeds and put in `./nist-nvdcve` directory

```bash
$ pip install cpe
$ python ./gen_cve_json.py
```

## Processing data source

- Integrate all JSON Feeds
- Remov unnessesary data fields
- Get product and vendor names from CPE (Common Platform Enumeration) URI
- Generate optimized JSON file as above

## Optimized data field

```json
[
    {
        "cve_id": string,
        "cwe_id": string[],
        "year": number,
        "descriptions": string[],
        "products": string[],
        "vendors": string[],
        "published_date": string,
        "last_modified_date": string,
        "cvssv2":
        {
            "base_metrics":
            {
                "access_vector": string (empty is ""),
                "access_complexity": string (empty is ""),
                "authentication": string (empty is ""),
                "confidentiality_impact": string (empty is ""),
                "integrity_impact": string (empty is ""),
                "availability_impact": string (empty is ""),
                "base_score": number (empty is -1)
            },
            "severity": string (empty is "")
        }
    },
    {...}
]
```
