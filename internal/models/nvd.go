package models

type CVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type CVSSMetric struct {
	CVSSData CVSSData `json:"cvssData"`
}

type Metrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
}

type CVE struct {
	ID      string  `json:"id"`
	Metrics Metrics `json:"metrics"`
}

type Vulnerability struct {
	CVE CVE `json:"cve"`
}

type NVDResponse struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}