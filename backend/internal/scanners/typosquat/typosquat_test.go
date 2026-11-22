package typosquat

import "testing"

func TestLookalike(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		// true positives
		{"lodahs", "lodash"},      // transposition
		{"expres", "express"},     // deletion
		{"expresss", "express"},   // insertion
		{"crossenv", "cross-env"}, // separator removed
		{"cross_env", "cross-env"},
		{"l0dash", "lodash"},          // digit/letter swap
		{"@type/node", "@types/node"}, // scope confusion
		{"typscrpt", "typescript"},    // distance 2, both names >= 8
		{"socket-io", "socket.io"},
		// true negatives
		{"lodash", ""},
		{"preact", ""},
		{"react-dom", ""},
		{"babel-core", ""},
		{"@babel/corr", ""}, // org scope: only Babel can publish there
		{"@types/nod", ""},  // same: only DefinitelyTyped publishes @types
		{"@types/ms", ""},   // real, one edit from @types/ws
		{"fsevents", ""},    // real, distance 2 from the short "events"
		{"reqeusts", ""},    // distance 2 but "request" is under 8 chars
		{"ms", ""},
		{"vue", ""},
		{"left-pad", ""},
		{"date-fns", ""},
		{"my-internal-thing", ""},
		{"react-ga", ""},
		{"", ""},
	} {
		got, ok := Lookalike(tc.name)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("Lookalike(%q) = %q, %v; want %q", tc.name, got, ok, tc.want)
		}
	}
}

func TestListSize(t *testing.T) {
	if len(rank) < 1000 {
		t.Fatalf("popular list has %d names, want >= 1000", len(rank))
	}
}

func BenchmarkLookalike3000(b *testing.B) {
	names := make([]string, 0, 3000)
	for n := range rank {
		names = append(names, n+"x")
		if len(names) == 3000 {
			break
		}
	}
	for b.Loop() {
		for _, n := range names {
			Lookalike(n)
		}
	}
}
