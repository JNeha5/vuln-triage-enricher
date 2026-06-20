package epss

import (
	"encoding/json"
	"io"
	"net/http"

	"vuln-triage/enricher/internal/models"
	"vuln-triage/enricher/internal/ratelimit"
)

func GetScore(cveID string) (models.EPSSResponse, error) {
	ratelimit.Wait()

	var result models.EPSSResponse

	url := "https://api.first.org/data/v1/epss?cve=" + cveID

	resp, err := http.Get(url)
	if err != nil {
		return result, err
	}
	
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

/*
Receive CVE
      ↓
Call EPSS API
      ↓
Read JSON
      ↓
Convert JSON to Struct
      ↓
Return Result
*/
