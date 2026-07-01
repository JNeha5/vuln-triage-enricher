package scoring

import "testing"

func TestCalculatePriorityHighRisk(t *testing.T) {

	score := CalculatePriority(
		10.0,
		"0.94",
		true,
	)

	if score != 100 {
		t.Errorf("Expected 100, got %v", score)
	}
}

func TestCalculatePriorityLowRisk(t *testing.T) {

	score := CalculatePriority(
		4.0,
		"0.10",
		false,
	)

	if score >= 50 {
		t.Errorf("Expected score below 50, got %v", score)
	}
}
