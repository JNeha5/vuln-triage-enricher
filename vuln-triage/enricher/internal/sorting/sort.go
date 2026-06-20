package sorting

import (
	"sort"

	"vuln-triage/enricher/internal/models"
)

func ByPriority(vulns []models.EnrichedVulnerability) {

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].PriorityScore > vulns[j].PriorityScore
	})
}
