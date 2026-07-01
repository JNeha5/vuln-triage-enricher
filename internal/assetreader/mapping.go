package assetreader

import (
	"encoding/csv"
	"os"
)

func ReadAssetMapping(filename string) (map[string]string, error) {

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	mapping := make(map[string]string)

	for i := 1; i < len(rows); i++ {
		mapping[rows[i][0]] = rows[i][1]
	}

	return mapping, nil
}
