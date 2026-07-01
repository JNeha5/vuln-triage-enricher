package enricher

import (
	"fmt"
	"sync"
	"vuln-triage/enricher/internal/cache"
	"vuln-triage/enricher/internal/epss"
	"vuln-triage/enricher/internal/kev"
	"vuln-triage/enricher/internal/models"
	"vuln-triage/enricher/internal/nvd"
	"vuln-triage/enricher/internal/scoring"
)

func BuildEnrichedVulnerability(
	cveID string,
	assetName string,
	assetWeight float64,
) (models.EnrichedVulnerability, error) {
	var enriched models.EnrichedVulnerability
	if cached, exists := cache.EnrichmentCache[cveID]; exists {
		fmt.Println("CACHE HIT:", cveID)
		return cached, nil
	}

	// NVD
	result, err := nvd.GetCVE(cveID)
	if err != nil {
		return enriched, err
	}

	if len(result.Vulnerabilities) == 0 {
		return enriched, nil
	}

	vuln := result.Vulnerabilities[0]

	var epssResult models.EPSSResponse
	var kevStatus bool

	var epssErr error
	var kevErr error

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		epssResult, epssErr = epss.GetScore(cveID)
	}()

	go func() {
		defer wg.Done()
		kevStatus, kevErr = kev.IsKnownExploited(cveID)
	}()

	wg.Wait()

	if epssErr != nil {
		return enriched, epssErr
	}

	if kevErr != nil {
		return enriched, kevErr
	}

	enriched = models.EnrichedVulnerability{
		CVEID:          vuln.CVE.ID,
		CVSSScore:      vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore,
		Severity:       vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity,
		KnownExploited: kevStatus,
		AssetName:      assetName,
		AssetWeight:    assetWeight,
	}

	if len(epssResult.Data) > 0 {
		enriched.EPSSScore = epssResult.Data[0].EPSS
		enriched.Percentile = epssResult.Data[0].Percentile
	}
	enriched.PriorityScore = scoring.CalculatePriority(
		enriched.CVSSScore,
		enriched.EPSSScore,
		enriched.KnownExploited, assetWeight,
	)
	enriched.RiskBand = scoring.GetRiskBand(
	enriched.PriorityScore,
    )
	cache.EnrichmentCache[cveID] = enriched

	return enriched, nil
}
func BuildMultipleEnrichedVulnerabilities(
	cveIDs []string,
	assetMapping map[string]string,
	assets map[string]float64,
) ([]models.EnrichedVulnerability, error) {
	var results []models.EnrichedVulnerability

	for _, cveID := range cveIDs {

		assetName := assetMapping[cveID]
		assetWeight := assets[assetName]

		enriched, err := BuildEnrichedVulnerability(
			cveID,
			assetName,
			assetWeight,
		)

		if err != nil {
			return nil, err
		}

		results = append(results, enriched)
	}

	return results, nil
}
