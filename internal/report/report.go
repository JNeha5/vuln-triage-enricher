package report

import (
	"encoding/csv"
	"os"
	"strconv"

	"vuln-triage/enricher/internal/models"
)

func WriteCSVReport(
	filename string,
	results []models.EnrichedVulnerability,
) error {

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{
		"CVE_ID",
		"CVSS",
		"SEVERITY",
		"EPSS",
		"KNOWN_EXPLOITED",
		"ASSET_NAME",
		"ASSET_WEIGHT",
		"PRIORITY_SCORE",
	})

	for _, result := range results {

		writer.Write([]string{
			result.CVEID,
			strconv.FormatFloat(result.CVSSScore, 'f', 2, 64),
			result.Severity,
			result.EPSSScore,
			strconv.FormatBool(result.KnownExploited),
			result.AssetName,
			strconv.FormatFloat(result.AssetWeight, 'f', 2, 64),
			strconv.FormatFloat(result.PriorityScore, 'f', 2, 64),
		})
	}

	return nil
}
