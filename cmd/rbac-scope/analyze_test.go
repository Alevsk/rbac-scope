package main

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/alevsk/rbac-scope/internal/ingestor"
)

func TestAnalyzeCmd_RunE(t *testing.T) {
	analyzeOpts = &ingestor.Options{} // ensure default
	analyzeOpts.OutputFormat = "json" // deterministic output
	cmd := analyzeCmd
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	cmd.SetContext(context.Background())
	err := cmd.RunE(cmd, []string{"../../internal/ingestor/testdata/valid.yaml"})
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var buf bytes.Buffer
	buf.ReadFrom(r)
	if buf.Len() == 0 {
		t.Error("no output")
	}
}

func TestAnalyzeCmd_RunE_Error(t *testing.T) {
	analyzeOpts = &ingestor.Options{}
	cmd := analyzeCmd
	cmd.SetContext(context.Background())
	if err := cmd.RunE(cmd, []string{"../../internal/ingestor/testdata/nonexistent.yaml"}); err == nil {
		t.Fatal("expected error")
	}
}
