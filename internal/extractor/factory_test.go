package extractor

import "testing"

func TestFactory_NewExtractor(t *testing.T) {
	f := NewExtractorFactory()

	id, err := f.NewExtractor(ExtractorTypeIdentity, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := id.(*IdentityExtractor); !ok {
		t.Errorf("expected IdentityExtractor, got %T", id)
	}

	wl, err := f.NewExtractor(ExtractorTypeWorkload, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := wl.(*WorkloadExtractor); !ok {
		t.Errorf("expected WorkloadExtractor, got %T", wl)
	}

	r, err := f.NewExtractor(ExtractorTypeRBAC, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := r.(*RBACExtractor); !ok {
		t.Errorf("expected RBACExtractor, got %T", r)
	}

	if _, err := f.NewExtractor("unknown", nil); err == nil {
		t.Errorf("expected error for unknown extractor type")
	}
}
