package csvreader

import (
	"encoding/csv"
	"os"
)

func ReadCVEs(filename string) ([]string, error) {

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var cves []string

	for i := 1; i < len(records); i++ { //We skip row 0 because it's the header.
		cves = append(cves, records[i][0])
	}

	return cves, nil
}
