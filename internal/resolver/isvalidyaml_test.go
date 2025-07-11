package resolver

import "testing"

func TestIsValidYAML(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
	}{
		{"empty", "", false},
		{"key value", "kind: Pod", true},
		{"dash", "- item", true},
		{"separator", "---", true},
		{"plain", "just text", false},
	}
	for _, c := range cases {
		if got := isValidYAML(c.input); got != c.want {
			t.Errorf("%s: expected %v got %v", c.name, c.want, got)
		}
	}
}
