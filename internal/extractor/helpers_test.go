package extractor

import "testing"

func TestToStringSlice(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  []string
	}{
		{"nil", nil, nil},
		{"slice of strings", []interface{}{"a", "b"}, []string{"a", "b"}},
		{"mixed types", []interface{}{"a", 1, "b"}, []string{"a", "b"}},
		{"wrong type", 42, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := toStringSlice(c.input)
			if len(got) != len(c.want) {
				t.Fatalf("expected %v got %v", c.want, got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("expected %v got %v", c.want, got)
				}
			}
		})
	}
}

func TestToStringMap(t *testing.T) {
	cases := []struct {
		name  string
		input interface{}
		want  map[string]string
	}{
		{"nil", nil, nil},
		{"map with strings", map[string]interface{}{"a": "1", "b": "2"}, map[string]string{"a": "1", "b": "2"}},
		{"map mixed", map[string]interface{}{"a": "1", "b": 2}, map[string]string{"a": "1"}},
		{"wrong type", 5, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := toStringMap(c.input)
			if len(got) != len(c.want) {
				t.Fatalf("expected %v got %v", c.want, got)
			}
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("expected %v got %v", c.want, got)
				}
			}
		})
	}
}

func TestGetTemplateSpec(t *testing.T) {
	spec := map[string]interface{}{
		"template": map[string]interface{}{
			"spec": map[string]interface{}{"a": 1},
		},
	}
	if m := getTemplateSpec(spec); m == nil || m["a"] != 1 {
		t.Fatalf("unexpected %v", m)
	}
	if getTemplateSpec(map[string]interface{}{"template": "bad"}) != nil {
		t.Fatalf("expected nil on bad template")
	}
	if getTemplateSpec(map[string]interface{}{}) != nil {
		t.Fatalf("expected nil on missing template")
	}
	spec2 := map[string]interface{}{"template": map[string]interface{}{"spec": "bad"}}
	if getTemplateSpec(spec2) != nil {
		t.Fatalf("expected nil on bad spec")
	}
}
