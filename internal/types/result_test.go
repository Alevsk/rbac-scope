package types

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestManifest(t *testing.T) {
	m := Manifest{
		Name:     "test-manifest",
		Content:  map[string]interface{}{"key": "value"},
		Raw:      []byte("raw data"),
		Metadata: map[string]interface{}{"meta_key": "meta_value"},
	}

	if m.Name != "test-manifest" {
		t.Errorf("Expected Name 'test-manifest', got '%s'", m.Name)
	}
	if !reflect.DeepEqual(m.Content, map[string]interface{}{"key": "value"}) {
		t.Errorf("Expected Content map[string]interface{}{\"key\": \"value\"}, got '%v'", m.Content)
	}
	if string(m.Raw) != "raw data" {
		t.Errorf("Expected Raw 'raw data', got '%s'", string(m.Raw))
	}
	if !reflect.DeepEqual(m.Metadata, map[string]interface{}{"meta_key": "meta_value"}) {
		t.Errorf("Expected Metadata map[string]interface{}{\"meta_key\": \"meta_value\"}, got '%v'", m.Metadata)
	}

	// Test empty/nil cases
	mEmpty := Manifest{}
	if mEmpty.Name != "" {
		t.Errorf("Expected empty Name, got '%s'", mEmpty.Name)
	}
	if mEmpty.Content != nil {
		t.Errorf("Expected nil Content, got '%v'", mEmpty.Content)
	}
}

func TestExtractedData(t *testing.T) {
	ed := ExtractedData{
		Data:     map[string]interface{}{"data_key": "data_value"},
		Metadata: map[string]interface{}{"meta_key": "meta_value"},
	}

	if !reflect.DeepEqual(ed.Data, map[string]interface{}{"data_key": "data_value"}) {
		t.Errorf("Expected Data map[string]interface{}{\"data_key\": \"data_value\"}, got '%v'", ed.Data)
	}
	if !reflect.DeepEqual(ed.Metadata, map[string]interface{}{"meta_key": "meta_value"}) {
		t.Errorf("Expected Metadata map[string]interface{}{\"meta_key\": \"meta_value\"}, got '%v'", ed.Metadata)
	}

	// Test empty/nil cases
	edEmpty := ExtractedData{}
	if edEmpty.Data != nil {
		t.Errorf("Expected nil Data, got '%v'", edEmpty.Data)
	}
	if edEmpty.Metadata != nil {
		t.Errorf("Expected nil Metadata, got '%v'", edEmpty.Metadata)
	}
}

func TestResult(t *testing.T) {
	ts := time.Now().Unix()
	testErr := errors.New("test error")

	r := Result{
		Version:   "v1.0.0",
		Name:      "test-result",
		Source:    "test-source",
		Success:   true,
		Error:     testErr,
		Timestamp: ts,
		Manifests: []*Manifest{
			{Name: "m1"},
		},
		Warnings:        []string{"warning1"},
		IdentityData:    &ExtractedData{Data: map[string]interface{}{"id_key": "id_value"}},
		WorkloadData:    &ExtractedData{Data: map[string]interface{}{"wl_key": "wl_value"}},
		RBACData:        &ExtractedData{Data: map[string]interface{}{"rbac_key": "rbac_value"}},
		OutputFormatted: "formatted output",
		Extra:           map[string]interface{}{"extra_key": "extra_value"},
	}

	if r.Version != "v1.0.0" {
		t.Errorf("Expected Version 'v1.0.0', got '%s'", r.Version)
	}
	if r.Name != "test-result" {
		t.Errorf("Expected Name 'test-result', got '%s'", r.Name)
	}
	if r.Source != "test-source" {
		t.Errorf("Expected Source 'test-source', got '%s'", r.Source)
	}
	if !r.Success {
		t.Errorf("Expected Success true, got %v", r.Success)
	}
	if r.Error != testErr {
		t.Errorf("Expected Error '%v', got '%v'", testErr, r.Error)
	}
	if r.Timestamp != ts {
		t.Errorf("Expected Timestamp %d, got %d", ts, r.Timestamp)
	}
	if len(r.Manifests) != 1 || r.Manifests[0].Name != "m1" {
		t.Errorf("Expected Manifests with one item named 'm1', got '%v'", r.Manifests)
	}
	if len(r.Warnings) != 1 || r.Warnings[0] != "warning1" {
		t.Errorf("Expected Warnings with one item 'warning1', got '%v'", r.Warnings)
	}
	if r.IdentityData == nil || r.IdentityData.Data["id_key"] != "id_value" {
		t.Errorf("Unexpected IdentityData: %v", r.IdentityData)
	}
	if r.WorkloadData == nil || r.WorkloadData.Data["wl_key"] != "wl_value" {
		t.Errorf("Unexpected WorkloadData: %v", r.WorkloadData)
	}
	if r.RBACData == nil || r.RBACData.Data["rbac_key"] != "rbac_value" {
		t.Errorf("Unexpected RBACData: %v", r.RBACData)
	}
	if r.OutputFormatted != "formatted output" {
		t.Errorf("Expected OutputFormatted 'formatted output', got '%s'", r.OutputFormatted)
	}
	if !reflect.DeepEqual(r.Extra, map[string]interface{}{"extra_key": "extra_value"}) {
		t.Errorf("Expected Extra map[string]interface{}{\"extra_key\": \"extra_value\"}, got '%v'", r.Extra)
	}

	// Test empty/nil/zero cases
	rEmpty := Result{}
	if rEmpty.Error != nil {
		t.Errorf("Expected nil Error, got '%v'", rEmpty.Error)
	}
	if rEmpty.Success {
		t.Errorf("Expected Success false, got %v", rEmpty.Success)
	}
}
