package vulndb

import "testing"

func TestBreakingSteps(t *testing.T) {
	for _, c := range []struct {
		from, to string
		want     int
	}{
		{"4.17.1", "4.21.2", 0},
		{"4.17.1", "4.17.3", 0},
		{"2.6.1", "3.1.10", 1},
		{"0.6.2", "4.0.10", 5}, // 0.x -> 1.0 then 1 -> 4
		{"0.6.2", "0.7.0", 1},
		{"0.1.7", "0.1.13", 0},
		{"0.0.8", "0.0.9", 1},
		{"0.0.8", "0.2.4", 1},
		{"3.0.0", "2.0.0", 0},
		{"latest", "1.0.0", -1},
	} {
		if got := BreakingSteps(c.from, c.to); got != c.want {
			t.Errorf("BreakingSteps(%s, %s) = %d, want %d", c.from, c.to, got, c.want)
		}
	}
}
