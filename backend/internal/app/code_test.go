package app

import (
	"testing"

	"limier/internal/scanners/source"
)

func TestMarkNew(t *testing.T) {
	prev := []source.Issue{{Rule: "r", File: "a.ts", Line: 3, Detail: "x"}}
	cur := []source.Issue{
		{Rule: "r", File: "a.ts", Line: 9, Detail: "x"},  // moved: not new
		{Rule: "r", File: "a.ts", Line: 12, Detail: "x"}, // second copy: new
		{Rule: "r", File: "b.ts", Detail: "x"},           // other file: new
	}
	markNew(prev, cur)
	if cur[0].New || !cur[1].New || !cur[2].New {
		t.Fatalf("got %+v", cur)
	}
}
