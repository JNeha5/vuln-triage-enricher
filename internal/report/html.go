package report

import (
	"html/template"
	"os"

	"vuln-triage/enricher/internal/models"
)

func WriteHTMLReport(
	filename string,
	results []models.EnrichedVulnerability,
) error {

	const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Triage Report</title>
    <style>
        table {
            border-collapse: collapse;
            width: 100%;
        }
        th, td {
            border: 1px solid black;
            padding: 8px;
        }
        th {
            background-color: #dddddd;
        }
    </style>
</head>
<body>

<h1>Vulnerability Triage Report</h1>

<table>
<tr>
    <th>CVE</th>
    <th>Priority</th>
    <th>Risk Band</th>
    <th>CVSS</th>
    <th>EPSS</th>
    <th>Asset</th>
</tr>

{{range .}}
<tr>
    <td>{{.CVEID}}</td>
    <td>{{.PriorityScore}}</td>
    <td>{{.RiskBand}}</td>
    <td>{{.CVSSScore}}</td>
    <td>{{.EPSSScore}}</td>
    <td>{{.AssetName}}</td>
</tr>
{{end}}

</table>

</body>
</html>
`

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, results)
}
