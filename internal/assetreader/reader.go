package assetreader

import (
	"encoding/csv"
	"os"
	"strconv"
	
)

func ReadAssets(filename string) (map[string]float64, error) {

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comma = ','

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	

	assets := make(map[string]float64)

	for i := 1; i < len(rows); i++ {
		if len(rows[i]) < 2 {

			continue
		}

		weight, err := strconv.ParseFloat(rows[i][1], 64)
		if err != nil {
			continue
		}

		assets[rows[i][0]] = weight
	}

	return assets, nil
}
