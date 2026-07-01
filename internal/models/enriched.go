package models

type EnrichedVulnerability struct {
	CVEID          string  `json:"cve_id"`
	CVSSScore      float64 `json:"cvss_score"`
	Severity       string  `json:"severity"`
	EPSSScore      string  `json:"epss_score"`
	Percentile     string  `json:"percentile"`
	KnownExploited bool    `json:"known_exploited"`

	AssetName   string  `json:"asset_name"`
	AssetWeight float64 `json:"asset_weight"`

	PriorityScore float64 `json:"priority_score"`
	RiskBand string `json:"risk_band"`
}
