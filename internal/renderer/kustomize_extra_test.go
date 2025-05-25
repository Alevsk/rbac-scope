package renderer

import "testing"

func TestKustomizeRenderer_Validate(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())

	valid := []byte("apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n")
	if err := r.Validate(valid); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	invalid := []byte("kind: NotKustomize")
	if err := r.Validate(invalid); err == nil {
		t.Fatal("expected error for invalid kustomization")
	}
}

func TestKustomizeRenderer_AddFileErrors(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())

	if err := r.AddFile("", []byte("data")); err == nil {
		t.Error("expected error for empty file name")
	}

	if err := r.AddFile("file.yaml", nil); err == nil {
		t.Error("expected error for nil content")
	}
}

func TestKustomizeRenderer_SetOptionsNil(t *testing.T) {
	r := NewKustomizeRenderer(DefaultOptions())
	if err := r.SetOptions(nil); err == nil {
		t.Fatal("expected error when options are nil")
	}
}
