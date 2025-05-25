package renderer

import "testing"

func TestHelmRenderer_AddFileErrors(t *testing.T) {
	r := NewHelmRenderer(DefaultOptions())

	if err := r.AddFile("", []byte("content")); err == nil {
		t.Error("expected error for empty file name")
	}

	if err := r.AddFile("file.yaml", nil); err == nil {
		t.Error("expected error for nil file content")
	}
}

func TestHelmRenderer_SetOptionsNil(t *testing.T) {
	r := NewHelmRenderer(DefaultOptions())
	if err := r.SetOptions(nil); err == nil {
		t.Fatal("expected error when setting nil options")
	}
}
