package scoring

func GetRiskBand(score float64) string {

	if score >= 90 {
		return "CRITICAL"
	}

	if score >= 70 {
		return "HIGH"
	}

	if score >= 40 {
		return "MEDIUM"
	}

	return "LOW"
}
