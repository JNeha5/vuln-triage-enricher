// separation of concerns.
package nvd

import (
	"encoding/json"
	"io"
	"net/http"
	"os"

	"vuln-triage/enricher/internal/models"
	"vuln-triage/enricher/internal/ratelimit"
	"vuln-triage/enricher/internal/retry"
)

func GetCVE(cveID string) (models.NVDResponse, error) {

	var result models.NVDResponse

	apiKey := os.Getenv("NVD_API_KEY")

	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result, err
	}

	req.Header.Set("apiKey", apiKey)

	client := &http.Client{}
	ratelimit.Wait()

	var resp *http.Response

	err = retry.Do(func() error {

		var retryErr error

		resp, retryErr = client.Do(req)

		return retryErr
	})

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
