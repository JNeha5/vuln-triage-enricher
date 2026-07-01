package main

import (
	"encoding/json"
	"fmt"
	"os"

	"vuln-triage/enricher/internal/assetreader"
	"vuln-triage/enricher/internal/csvreader"
	"vuln-triage/enricher/internal/enricher"
	"vuln-triage/enricher/internal/sorting"
	"vuln-triage/enricher/internal/report"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("go run main.go CVE-2021-44228")
		fmt.Println("go run main.go CVE-2021-44228 CVE-2024-3094")
		fmt.Println("go run main.go input/cves.csv")
		return
	}

	var cveIDs []string

	input := os.Args[1]

	if len(input) >= 4 && input[len(input)-4:] == ".csv" {

		cves, err := csvreader.ReadCVEs(input)
		if err != nil {
			fmt.Println("CSV Error:", err)
			return
		}

		cveIDs = cves

	} else {

		cveIDs = os.Args[1:]
	}

	assets, err := assetreader.ReadAssets("input/assets.csv")
	
	if err != nil {
		fmt.Println("Assets Error:", err)
		return
	}
	

	assetMapping, err := assetreader.ReadAssetMapping("input/asset_mapping.csv")
	if err != nil {
		fmt.Println("Asset Mapping Error:", err)
		return
	}
	

	results, err := enricher.BuildMultipleEnrichedVulnerabilities(
		cveIDs,
		assetMapping,
		assets,
	)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	sorting.ByPriority(results)
	err = report.WriteCSVReport(
	"output/report.csv",
	results,
    )
    if err != nil {
	    fmt.Println("Report Error:", err)
	    return
    }
	err = report.WriteHTMLReport(
	"output/report.html",
	results,
    )
    if err != nil {
	    fmt.Println("HTML Report Error:", err)
	    return
    }

	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Println("JSON Error:", err)
		return
	}

	err = os.WriteFile("output/enriched.json", jsonData, 0644)
	if err != nil {
		fmt.Println("File Error:", err)
		return
	}

	fmt.Println("enriched.json created successfully")

	for _, result := range results {

		fmt.Println("------------------------")
		fmt.Println("CVE ID:", result.CVEID)
		fmt.Println("CVSS Score:", result.CVSSScore)
		fmt.Println("Severity:", result.Severity)
		fmt.Println("EPSS Score:", result.EPSSScore)
		fmt.Println("Percentile:", result.Percentile)
		fmt.Println("Known Exploited:", result.KnownExploited)
		fmt.Println("Priority Score:", result.PriorityScore)
	}
}
