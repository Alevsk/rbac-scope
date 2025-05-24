package renderer

import (
	"context"
	"testing"
)

// mockRenderer implements the Renderer interface for testing
type mockRenderer struct {
	opts *Options
}

func (r *mockRenderer) Render(_ context.Context, _ []byte) (*Result, error) {
	return &Result{}, nil
}

func (r *mockRenderer) Validate(_ []byte) error {
	return nil
}

func (r *mockRenderer) ValidateSchema(_ []byte) error {
	return nil
}

func (r *mockRenderer) SetOptions(opts *Options) error {
	if opts == nil {
		return ErrInvalidInput
	}
	r.opts = opts
	return nil
}

func (r *mockRenderer) GetOptions() *Options {
	if r.opts == nil {
		return DefaultOptions()
	}
	return r.opts
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if !opts.ValidateOutput {
		t.Error("ValidateOutput should be true by default")
	}

	if !opts.IncludeMetadata {
		t.Error("IncludeMetadata should be true by default")
	}

	if opts.OutputFormat != "yaml" {
		t.Errorf("OutputFormat should be 'yaml' by default, got %s", opts.OutputFormat)
	}
}

func TestRendererInterface(t *testing.T) {
	r := &mockRenderer{}

	// Test GetOptions returns default options when not set
	defaultOpts := r.GetOptions()
	if defaultOpts.OutputFormat != "yaml" {
		t.Errorf("Expected default output format 'yaml', got %s", defaultOpts.OutputFormat)
	}

	// Test SetOptions with nil
	if err := r.SetOptions(nil); err != ErrInvalidInput {
		t.Errorf("Expected ErrInvalidInput, got %v", err)
	}

	// Test SetOptions with valid options
	customOpts := &Options{OutputFormat: "json"}
	if err := r.SetOptions(customOpts); err != nil {
		t.Errorf("SetOptions failed: %v", err)
	}

	// Test GetOptions returns updated options
	updatedOpts := r.GetOptions()
	if updatedOpts.OutputFormat != "json" {
		t.Errorf("Expected output format 'json', got %s", updatedOpts.OutputFormat)
	}
}
