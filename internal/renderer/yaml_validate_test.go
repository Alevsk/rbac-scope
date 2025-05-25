package renderer

import "testing"

func TestYAMLRenderer_Validate(t *testing.T) {
	h := newTestHelper(t)
	r := NewYAMLRenderer()

	valid := h.readFixture("role.yaml")
	if err := r.Validate(valid); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	invalid := h.readFixture("invalid.yaml")
	if err := r.Validate(invalid); err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	if err := r.Validate([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}
