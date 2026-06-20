/*KEV is usually consumed as a:

JSON Feed

Your program will:

Download KEV Feed
        ↓
Search for CVE
        ↓
Return True/False*/

package models

type KEVVulnerability struct {
	CVEID string `json:"cveID"`
}

type KEVResponse struct {
	Vulnerabilities []KEVVulnerability `json:"vulnerabilities"`
}
