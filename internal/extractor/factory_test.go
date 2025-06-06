package extractor

import (
	"reflect"
	"testing"
)

func TestNewExtractorFactory(t *testing.T) {
	factory := NewExtractorFactory()
	if factory == nil {
		t.Error("NewExtractorFactory() returned nil")
	}
}

func TestDefaultExtractorFactory_NewExtractor(t *testing.T) {
	factory := NewExtractorFactory()

	defaultOpts := DefaultOptions()
	customOpts := &Options{StrictParsing: true, IncludeMetadata: false}

	tests := []struct {
		name          string
		extractorType ExtractorType
		opts          *Options
		wantType      reflect.Type
		wantErr       bool
		checkOpts     bool // whether to check if options were set correctly
	}{
		{
			name:          "identity extractor with default options",
			extractorType: ExtractorTypeIdentity,
			opts:          nil, // Will use default options
			wantType:      reflect.TypeOf(&IdentityExtractor{}),
			wantErr:       false,
			checkOpts:     true, // Check against defaultOpts
		},
		{
			name:          "identity extractor with custom options",
			extractorType: ExtractorTypeIdentity,
			opts:          customOpts,
			wantType:      reflect.TypeOf(&IdentityExtractor{}),
			wantErr:       false,
			checkOpts:     true,
		},
		{
			name:          "workload extractor with default options",
			extractorType: ExtractorTypeWorkload,
			opts:          nil,
			wantType:      reflect.TypeOf(&WorkloadExtractor{}),
			wantErr:       false,
			checkOpts:     true, // Check against defaultOpts
		},
		{
			name:          "workload extractor with custom options",
			extractorType: ExtractorTypeWorkload,
			opts:          customOpts,
			wantType:      reflect.TypeOf(&WorkloadExtractor{}),
			wantErr:       false,
			checkOpts:     true,
		},
		{
			name:          "rbac extractor with default options",
			extractorType: ExtractorTypeRBAC,
			opts:          nil,
			wantType:      reflect.TypeOf(&RBACExtractor{}),
			wantErr:       false,
			checkOpts:     true, // Check against defaultOpts
		},
		{
			name:          "rbac extractor with custom options",
			extractorType: ExtractorTypeRBAC,
			opts:          customOpts,
			wantType:      reflect.TypeOf(&RBACExtractor{}),
			wantErr:       false,
			checkOpts:     true,
		},
		{
			name:          "unknown extractor type",
			extractorType: "unknown",
			opts:          defaultOpts,
			wantType:      nil,
			wantErr:       true,
			checkOpts:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := factory.NewExtractor(tt.extractorType, tt.opts)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewExtractor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if extractor == nil {
					t.Errorf("NewExtractor() returned nil extractor when no error was expected")
					return
				}
				gotType := reflect.TypeOf(extractor)
				if gotType != tt.wantType {
					t.Errorf("NewExtractor() got type %v, want type %v", gotType, tt.wantType)
				}

				if tt.checkOpts {
					gotOpts := extractor.GetOptions()
					expectedOpts := tt.opts
					if expectedOpts == nil { // Was default case
						expectedOpts = defaultOpts
					}
					if !reflect.DeepEqual(gotOpts, expectedOpts) {
						t.Errorf("NewExtractor() options = %v, want %v", gotOpts, expectedOpts)
					}
				}
			}
		})
	}
}
