package renderer

import "testing"

// TestRendererFactory_GetRenderer verifies that the factory returns the correct renderer type
// and applies default options when none are provided.
func TestRendererFactory_GetRenderer(t *testing.T) {
	factory := NewRendererFactory(nil)

	r, err := factory.GetRenderer(RendererTypeYAML)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := r.(*YAMLRenderer); !ok {
		t.Fatalf("expected YAMLRenderer, got %T", r)
	}

	opts := r.GetOptions()
	if opts.OutputFormat != DefaultOptions().OutputFormat {
		t.Errorf("expected default output format %s, got %s", DefaultOptions().OutputFormat, opts.OutputFormat)
	}
}

// TestRendererFactory_InvalidType ensures that requesting an unknown renderer type
// returns ErrInvalidFormat.
func TestRendererFactory_InvalidType(t *testing.T) {
	factory := NewRendererFactory(nil)
	if _, err := factory.GetRenderer(RendererType("unknown")); err == nil {
		t.Fatal("expected error for unknown renderer type")
	}
}
