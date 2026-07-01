package cache

import "vuln-triage/enricher/internal/models"

var EnrichmentCache = make(map[string]models.EnrichedVulnerability)
