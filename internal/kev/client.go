package kev

import (
	"encoding/json"
	"io"
	"net/http"

	
	"vuln-triage/enricher/internal/models"
)

func GetKEVFeed() (models.KEVResponse, error) {

	var result models.KEVResponse

	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	resp, err := http.Get(url)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	//fmt.Println("KEV Response:")
	//fmt.Println(string(body))

	err = json.Unmarshal(body, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func IsKnownExploited(cveID string) (bool, error) {

	feed, err := GetKEVFeed()
	if err != nil {
		return false, err
	}

	for _, vuln := range feed.Vulnerabilities {
		if vuln.CVEID == cveID {
			return true, nil
		}
	}

	return false, nil
}
