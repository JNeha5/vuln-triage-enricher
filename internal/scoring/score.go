package scoring

import (
	"math"
	"strconv"
)
func CalculatePriority(
	cvss float64,
	epss string,
	kev bool,
	assetWeight float64,
) float64 {


	epssValue, err := strconv.ParseFloat(epss, 64)
	if err != nil {
		epssValue = 0
	}

	cvssNorm := cvss / 10.0

	score := 100 * (
	0.4*cvssNorm +
		0.4*epssValue +
		0.2*assetWeight)

	if kev {
		score += 20
	}

	score = math.Min(score, 100)

	return math.Round(score*100) / 100
}