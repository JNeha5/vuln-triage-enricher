# Vulnerability Triage & Enrichment Engine

A Go-based vulnerability triage engine that enriches CVEs using multiple threat intelligence sources and prioritizes them based on exploitability, severity, and asset criticality.

## Features

- Fetches CVE details from the NVD API
- Retrieves EPSS scores
- Checks CISA Known Exploited Vulnerabilities (KEV)
- Supports CSV input of CVEs
- Supports asset-to-CVE mapping
- Calculates an asset-aware priority score
- Assigns Risk Bands (Critical, High, Medium, Low)
- Uses concurrency to speed up API calls
- Implements in-memory caching
- Includes rate limiting and retry logic
- Generates:
  - JSON report
  - CSV report
  - HTML report
- Includes unit tests for scoring logic

---

## Project Structure

```
enricher/
├── input/
├── internal/
│   ├── assetreader/
│   ├── cache/
│   ├── csvreader/
│   ├── enricher/
│   ├── epss/
│   ├── kev/
│   ├── models/
│   ├── nvd/
│   ├── ratelimit/
│   ├── report/
│   ├── retry/
│   ├── scoring/
│   └── sorting/
├── output/
├── go.mod
├── main.go
└── README.md
```

---

## Data Sources

- National Vulnerability Database (NVD)
- Exploit Prediction Scoring System (EPSS)
- CISA Known Exploited Vulnerabilities (KEV)

---

## Priority Score

The priority score combines:

- CVSS Score
- EPSS Score
- KEV Status
- Asset Criticality

Higher scores indicate vulnerabilities that should be remediated first.

---

## Risk Bands

| Priority Score | Risk Band |
|---------------|-----------|
| 90–100 | CRITICAL |
| 70–89 | HIGH |
| 40–69 | MEDIUM |
| 0–39 | LOW |

---

## Input Files

### CVEs

```
cve_id
CVE-2021-44228
CVE-2024-3094
```

### Assets

```
asset_name,asset_weight
database-server,0.9
web-server,0.8
developer-laptop,0.4
```

### Asset Mapping

```
cve_id,asset_name
CVE-2021-44228,database-server
CVE-2024-3094,web-server
```

---

## Running the Project

Run a single CVE:

```bash
go run main.go CVE-2021-44228
```

Run multiple CVEs:

```bash
go run main.go CVE-2021-44228 CVE-2024-3094
```

Run from CSV:

```bash
go run main.go input/cves.csv
```

---

## Output

The application generates:

- `output/enriched.json`
- `output/report.csv`
- `output/report.html`

---

## Technologies Used

- Go
- NVD API
- EPSS API
- CISA KEV Feed
- Goroutines
- WaitGroup
- JSON
- CSV
- HTML Templates

---

## Future Improvements

- PDF report generation
- SQLite/PostgreSQL support
- REST API interface
- Docker support
- Web dashboard

---

## Author

**J Neha**