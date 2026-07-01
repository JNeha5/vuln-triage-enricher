package scoring

import (
	"math"
	"strconv"
)

func CalculatePriority(cvss float64, epss string, kev bool) float64 {

	epssValue, err := strconv.ParseFloat(epss, 64)
	if err != nil {
		epssValue = 0
	}

	cvssNorm := cvss / 10.0

	score := 100 * (
		0.5*cvssNorm +
			0.5*epssValue)

	if kev {
		score += 20
	}

	score = math.Min(score, 100)

	return math.Round(score*100) / 100
}