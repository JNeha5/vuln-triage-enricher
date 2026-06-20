package models

type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
}

type EPSSResponse struct {
	Status string     `json:"status"`
	Data   []EPSSData `json:"data"`
}
