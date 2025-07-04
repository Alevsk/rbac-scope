package formatter

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/alevsk/rbac-scope/internal/config"
	"github.com/alevsk/rbac-scope/internal/extractor"
	"github.com/alevsk/rbac-scope/internal/logger"
	"github.com/alevsk/rbac-scope/internal/policyevaluation"
	"github.com/alevsk/rbac-scope/internal/types"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()
	if !opts.IncludeMetadata {
		t.Errorf("DefaultOptions().IncludeMetadata = false, want true")
	}
}

func TestParseType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType Type
		wantErr  bool
	}{
		{"json", "json", TypeJSON, false},
		{"yaml", "yaml", TypeYAML, false},
		{"table", "table", TypeTable, false},
		{"markdown", "markdown", TypeMarkdown, false},
		{"unknown", "unknown", "", true},
		{"empty", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, err := ParseType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotType != tt.wantType {
				t.Errorf("ParseType() gotType = %v, want %v", gotType, tt.wantType)
			}
		})
	}
}

func TestNewFormatter(t *testing.T) {
	validTypes := []struct {
		name          string
		formatterType Type
		expectedKind  reflect.Kind
	}{
		{"json", TypeJSON, reflect.TypeOf(&JSON{}).Kind()},
		{"yaml", TypeYAML, reflect.TypeOf(&YAML{}).Kind()},
		{"table", TypeTable, reflect.TypeOf(&Table{}).Kind()},
		{"markdown", TypeMarkdown, reflect.TypeOf(&Markdown{}).Kind()},
	}

	for _, tt := range validTypes {
		t.Run(tt.name+"_nil_options", func(t *testing.T) {
			formatter, err := NewFormatter(tt.formatterType, nil)
			if err != nil {
				t.Fatalf("NewFormatter(%q, nil) error = %v, want nil", tt.formatterType, err)
			}
			if formatter == nil {
				t.Fatalf("NewFormatter(%q, nil) formatter = nil, want non-nil", tt.formatterType)
			}
			switch f := formatter.(type) {
			case *JSON:
				if !f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = false, want true for default options")
				}
			case *YAML:
				if !f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = false, want true for default options")
				}
			case *Table:
				if !f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = false, want true for default options")
				}
			case *Markdown:
				if !f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = false, want true for default options")
				}
			default:
				t.Errorf("NewFormatter returned an unexpected type: %T", formatter)
			}
		})
	}

	customOpts := &Options{IncludeMetadata: false}
	for _, tt := range validTypes {
		t.Run(tt.name+"_custom_options", func(t *testing.T) {
			formatter, err := NewFormatter(tt.formatterType, customOpts)
			if err != nil {
				t.Fatalf("NewFormatter(%q, customOpts) error = %v, want nil", tt.formatterType, err)
			}
			if formatter == nil {
				t.Fatalf("NewFormatter(%q, customOpts) formatter = nil, want non-nil", tt.formatterType)
			}
			switch f := formatter.(type) {
			case *JSON:
				if f.opts != customOpts {
					t.Errorf("formatter.opts not set to customOpts")
				}
				if f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = true, want false for custom options")
				}
			case *YAML:
				if f.opts != customOpts {
					t.Errorf("formatter.opts not set to customOpts")
				}
				if f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = true, want false for custom options")
				}
			case *Table:
				if f.opts != customOpts {
					t.Errorf("formatter.opts not set to customOpts")
				}
				if f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = true, want false for custom options")
				}
			case *Markdown:
				if f.opts != customOpts {
					t.Errorf("formatter.opts not set to customOpts")
				}
				if f.opts.IncludeMetadata {
					t.Errorf("formatter.opts.IncludeMetadata = true, want false for custom options")
				}
			default:
				t.Errorf("NewFormatter returned an unexpected type: %T", formatter)
			}
		})
	}

	t.Run("unknown_type", func(t *testing.T) {
		formatter, err := NewFormatter("unknown", nil)
		if err == nil {
			t.Errorf("NewFormatter(\"unknown\", nil) error = nil, want non-nil error")
		}
		if formatter != nil {
			t.Errorf("NewFormatter(\"unknown\", nil) formatter = %v, want nil", formatter)
		}
	})
}

func newTestResult(name, version, source string, ts int64) types.Result {
	identityData := make(map[string]interface{})
	identityData["identities"] = make(map[string]map[string]extractor.Identity)

	rbacData := make(map[string]interface{})
	rbacData["rbac"] = make(map[string]map[string]extractor.ServiceAccountRBAC)

	workloadData := make(map[string]interface{})
	workloadData["workloads"] = make(map[string]map[string][]extractor.Workload)

	return types.Result{
		Name:         name,
		Version:      version,
		Source:       source,
		Timestamp:    ts,
		IdentityData: &types.ExtractedData{Data: identityData},
		RBACData:     &types.ExtractedData{Data: rbacData},
		WorkloadData: &types.ExtractedData{Data: workloadData},
	}
}

func addRawIdentityData(res *types.Result, saName, saNamespace string, identity extractor.Identity) {
	identitiesMap := res.IdentityData.Data["identities"].(map[string]map[string]extractor.Identity)
	if _, ok := identitiesMap[saName]; !ok {
		identitiesMap[saName] = make(map[string]extractor.Identity)
	}
	identitiesMap[saName][saNamespace] = identity
}

func addRawRBACData(res *types.Result, saName, saNamespace string, rbac extractor.ServiceAccountRBAC) {
	rbacMap := res.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
	if _, ok := rbacMap[saName]; !ok {
		rbacMap[saName] = make(map[string]extractor.ServiceAccountRBAC)
	}
	rbacMap[saName][saNamespace] = rbac
}

func addRawWorkloadData(res *types.Result, workloads []extractor.Workload) {
	workloadMap := res.WorkloadData.Data["workloads"].(map[string]map[string][]extractor.Workload)
	for _, wl := range workloads {
		if _, ok := workloadMap[wl.ServiceAccount]; !ok {
			workloadMap[wl.ServiceAccount] = make(map[string][]extractor.Workload)
		}
		workloadMap[wl.ServiceAccount][wl.Namespace] = append(workloadMap[wl.ServiceAccount][wl.Namespace], wl)
	}
}

func sortSARoleBindingEntries(entries []SARoleBindingEntry) {
	for i := range entries {
		sort.Strings(entries[i].Verbs)
		sort.Slice(entries[i].Tags, func(k, l int) bool { return entries[i].Tags[k] < entries[i].Tags[l] })
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].ServiceAccountName != entries[j].ServiceAccountName {
			return entries[i].ServiceAccountName < entries[j].ServiceAccountName
		}
		if entries[i].Namespace != entries[j].Namespace {
			return entries[i].Namespace < entries[j].Namespace
		}
		if entries[i].RoleType != entries[j].RoleType {
			return entries[i].RoleType < entries[j].RoleType
		}
		if entries[i].RoleName != entries[j].RoleName {
			return entries[i].RoleName < entries[j].RoleName
		}
		if entries[i].APIGroup != entries[j].APIGroup {
			return entries[i].APIGroup < entries[j].APIGroup
		}
		if entries[i].Resource != entries[j].Resource {
			return entries[i].Resource < entries[j].Resource
		}
		verbI := strings.Join(entries[i].Verbs, ",")
		verbJ := strings.Join(entries[j].Verbs, ",")
		if verbI != verbJ {
			return verbI < verbJ
		}
		return entries[i].RiskLevel < entries[j].RiskLevel
	})
}

func TestPrepareData(t *testing.T) {
	// Common setup for all tests
	cfg := &config.Config{Debug: false}
	logger.Init(cfg)
	timestamp := time.Now().Unix()

	// Define the test table
	testCases := []struct {
		name       string
		inputRes   func(timestamp int64) types.Result
		inputOpts  *Options
		wantParsed ParsedData
		wantErrStr string
		checkFunc  func(t *testing.T, got ParsedData, want ParsedData)
	}{
		{
			name: "empty result with metadata",
			inputRes: func(ts int64) types.Result {
				return newTestResult("empty", "v0", "src", ts)
			},
			inputOpts: DefaultOptions(),
			wantParsed: ParsedData{
				Metadata: &Metadata{
					Name:      "empty",
					Version:   "v0",
					Source:    "src",
					Timestamp: timestamp,
				},
				IdentityData: []SAIdentityEntry{},
				RBACData:     []SARoleBindingEntry{},
				WorkloadData: []SAWorkloadEntry{},
			},
		},
		{
			name: "no metadata included",
			inputRes: func(ts int64) types.Result {
				return newTestResult("test", "v1", "src", ts)
			},
			inputOpts: &Options{IncludeMetadata: false},
			wantParsed: ParsedData{
				Metadata:     nil,
				IdentityData: []SAIdentityEntry{},
				RBACData:     []SARoleBindingEntry{},
				WorkloadData: []SAWorkloadEntry{},
			},
		},
		{
			name: "invalid identity data format",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("test", "v1", "src", ts)
				res.IdentityData.Data["identities"] = "this is not a map"
				return res
			},
			inputOpts:  DefaultOptions(),
			wantErrStr: "invalid Identity data format",
		},
		{
			name: "invalid rbac data format",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("test", "v1", "src", ts)
				res.RBACData.Data["rbac"] = "this is not a map"
				return res
			},
			inputOpts:  DefaultOptions(),
			wantErrStr: "invalid RBAC data format",
		},
		{
			name: "invalid workload data format",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("test", "v1", "src", ts)
				res.WorkloadData.Data["workloads"] = "this is not a map"
				return res
			},
			inputOpts:  DefaultOptions(),
			wantErrStr: "invalid Workload data format",
		},
		{
			name: "full data with metadata",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("full-app", "v1.1", "full-src", ts)
				addRawIdentityData(&res, "sa1", "ns1", extractor.Identity{
					Name:             "sa1",
					Namespace:        "ns1",
					AutomountToken:   true,
					Secrets:          []string{"s1"},
					ImagePullSecrets: []string{"ips1"},
				})
				addRawRBACData(&res, "sa1", "ns1", extractor.ServiceAccountRBAC{
					Roles: []extractor.RBACRole{
						{
							Type:      "Role",
							Name:      "role1",
							Namespace: "ns1",
							Permissions: extractor.RuleApiGroup{
								"": extractor.RuleResource{
									"pods": extractor.RuleResourceName{
										"": extractor.RuleVerb{
											"get":  {},
											"list": {},
										},
									},
								},
							},
						},
						{
							Type:      "ClusterRole",
							Name:      "clusterrole1",
							Namespace: "*",
							Permissions: extractor.RuleApiGroup{
								"apps": extractor.RuleResource{
									"deployments": extractor.RuleResourceName{
										"": extractor.RuleVerb{
											"watch": {},
										},
									},
								},
							},
						},
					},
				})
				addRawWorkloadData(&res, []extractor.Workload{
					{
						Type:           "Deployment",
						Name:           "dep1",
						Namespace:      "ns1",
						ServiceAccount: "sa1",
						Containers: []extractor.Container{
							{
								Name:  "c1",
								Image: "img1",
							},
						},
					},
				})
				return res
			},
			inputOpts: DefaultOptions(),
			wantParsed: ParsedData{ // Populate the expected simple parts
				Metadata: &Metadata{
					Name:      "full-app",
					Version:   "v1.1",
					Source:    "full-src",
					Timestamp: timestamp,
				},
				IdentityData: []SAIdentityEntry{
					{
						ServiceAccountName: "sa1",
						Namespace:          "ns1",
						AutomountToken:     true,
						Secrets:            []string{"s1"},
						ImagePullSecrets:   []string{"ips1"},
					},
				},
				WorkloadData: []SAWorkloadEntry{
					{
						ServiceAccountName: "sa1",
						Namespace:          "ns1",
						WorkloadType:       "Deployment",
						WorkloadName:       "dep1",
						ContainerName:      "c1",
						Image:              "img1",
					},
				},
				RBACData: []SARoleBindingEntry{ // This part will be checked by the custom checkFunc
					{
						ServiceAccountName: "sa1",
						Namespace:          "ns1",
						RoleType:           "Role",
						RoleName:           "role1",
						APIGroup:           "",
						Resource:           "pods",
						Verbs:              []string{"get", "list"},
						RiskLevel:          "Low",
						Tags:               policyevaluation.RiskTags{},
						MatchedRiskRules: []SARoleBindingRiskRule{
							{
								ID:   9996,
								Name: "Base Risk Level - Low",
								Link: "https://rbac-atlas.github.io/rules/9996/",
							},
						},
					},
					{
						ServiceAccountName: "sa1",
						Namespace:          "ns1",
						RoleType:           "ClusterRole",
						RoleName:           "clusterrole1",
						APIGroup:           "apps",
						Resource:           "deployments",
						Verbs:              []string{"watch"},
						RiskLevel:          "Low",
						Tags:               policyevaluation.RiskTags{},
						MatchedRiskRules: []SARoleBindingRiskRule{
							{
								ID:   9996,
								Name: "Base Risk Level - Low",
								Link: "https://rbac-atlas.github.io/rules/9996/",
							},
						},
					},
				},
			},
			checkFunc: func(t *testing.T, got ParsedData, want ParsedData) {
				// Custom check for RBAC data due to its complexity and need for sorting.
				sortSARoleBindingEntries(got.RBACData)
				sortSARoleBindingEntries(want.RBACData)

				// Use cmp.Diff for a powerful, detailed comparison.
				// We ignore the RBACData in this top-level diff because we're comparing it manually.
				if diff := cmp.Diff(want, got, cmpopts.IgnoreFields(ParsedData{}, "RBACData")); diff != "" {
					t.Errorf("ParsedData mismatch (-want +got):\n%s", diff)
				}

				// Now compare the sorted RBAC data separately.
				if diff := cmp.Diff(want.RBACData, got.RBACData); diff != "" {
					t.Errorf("ParsedData.RBACData mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			name: "rbac data with risk evaluation",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("risk-app", "v1", "risk-src", ts)
				addRawRBACData(&res, "risk-sa", "default", extractor.ServiceAccountRBAC{
					Roles: []extractor.RBACRole{{
						Type: "ClusterRole", Name: "super-admin-role", Namespace: "*",
						Permissions: extractor.RuleApiGroup{
							"*": extractor.RuleResource{
								"*": extractor.RuleResourceName{
									"*": extractor.RuleVerb{
										"*": {}},
								},
							},
						},
					}},
				})
				return res
			},
			inputOpts: DefaultOptions(),
			checkFunc: func(t *testing.T, got ParsedData, want ParsedData) {
				if len(got.RBACData) != 1 {
					t.Fatalf("RBACData len got %d, want 1. Got: %+v", len(got.RBACData), got.RBACData)
				}
				entry := got.RBACData[0]
				if entry.RiskLevel != "Critical" {
					t.Errorf("RBACData[0].RiskLevel is %q, want 'Critical'", entry.RiskLevel)
				}
				found := false
				for _, tag := range entry.Tags {
					if tag == "ClusterAdminAccess" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("RBACData[0].Tags %v does not contain 'ClusterAdminAccess'", entry.Tags)
				}
				// You might want a more robust check for RiskRules, e.g., checking for presence
				// of a few key rules instead of a brittle deep equal on a long, generated slice.
				if len(entry.MatchedRiskRules) == 0 {
					t.Error("RBACData[0].RiskRules should not be empty for a critical risk")
				}
			},
		},
	}

	// Run the tests
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			res := tc.inputRes(timestamp)
			opts := tc.inputOpts

			// Act
			parsed, err := PrepareData(res, opts)

			// Assert
			if tc.wantErrStr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, but got nil", tc.wantErrStr)
				}
				if !strings.Contains(err.Error(), tc.wantErrStr) {
					t.Errorf("expected error to contain %q, got %q", tc.wantErrStr, err.Error())
				}
				return // Test is done for expected error cases
			}

			if err != nil {
				t.Fatalf("PrepareData() returned an unexpected error: %v", err)
			}

			if tc.checkFunc != nil {
				// Use the custom validation function if provided
				tc.checkFunc(t, parsed, tc.wantParsed)
			} else {
				// Otherwise, use a standard deep comparison
				// Using cmp.Diff provides much better output on failure than reflect.DeepEqual
				if diff := cmp.Diff(tc.wantParsed, parsed, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("PrepareData() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// NOTE: Tests for Format methods, and buildTables will be added in subsequent phases.

func getTestResultData(testCase string) types.Result {
	// Helper to create consistent test data
	timestamp := time.Now().Unix()
	res := newTestResult("test-app", "v1.0", "test-src", timestamp)

	// Create invalid data for specific test cases
	switch testCase {
	case "JSON_MarshalError":
		// Create a circular reference that cannot be marshaled to JSON
		circular := make(map[string]interface{})
		circular["self"] = circular
		res.Extra = circular
		return res
	case "YAML_MarshalPanic":
		// Create a function value that cannot be marshaled to YAML and will panic
		res.Extra = map[string]interface{}{
			"fn": func() {},
		}
		return res
	case "YAML_MarshalError":
		// Create a channel which will cause yaml.Marshal to return an error without panicking
		res.Extra = map[string]interface{}{
			"ch": make(chan int),
		}
		return res
	}
	addRawIdentityData(&res, "sa1", "ns1", extractor.Identity{Name: "sa1", Namespace: "ns1", AutomountToken: true, Secrets: []string{"s1"}, ImagePullSecrets: []string{"ips1"}})
	saRBACEntryData := extractor.ServiceAccountRBAC{
		Roles: []extractor.RBACRole{
			{
				Type:      "Role",
				Name:      "pod-reader",
				Namespace: "ns1",
				Permissions: extractor.RuleApiGroup{
					"": extractor.RuleResource{"pods": extractor.RuleResourceName{"my-pod": extractor.RuleVerb{"get": struct{}{}, "list": struct{}{}}}},
				},
			},
		},
	}
	addRawRBACData(&res, "sa1", "ns1", saRBACEntryData)
	addRawWorkloadData(&res, []extractor.Workload{
		{Type: "Deployment", Name: "app-dep", Namespace: "ns1", ServiceAccount: "sa1", Containers: []extractor.Container{{Name: "main", Image: "app-image"}}},
	})
	return res
}

func TestFormatters(t *testing.T) {
	testData := getTestResultData("")
	optsWithMeta := DefaultOptions()
	optsNoMeta := &Options{IncludeMetadata: false}

	testCases := []struct {
		name          string
		formatterType Type
		opts          *Options
		expectedError bool
		checkOutput   func(t *testing.T, output string) // Specific checks for output
		getTestData   func() types.Result               // Optional function to get test data for this case
	}{
		// JSON Formatter Tests
		{
			name:          "JSON_WithMetadata",
			formatterType: TypeJSON,
			opts:          optsWithMeta,
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := json.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal JSON output: %v. Output:\n%s", err, output)
				}
				if data.Metadata == nil {
					t.Fatal("JSON output with metadata: Metadata field is nil")
				}
				if data.Metadata.Name != "test-app" {
					t.Errorf("JSON Metadata.Name got %s, want test-app", data.Metadata.Name)
				}
				if len(data.RBACData) == 0 || data.RBACData[0].ServiceAccountName != "sa1" {
					t.Errorf("JSON RBACData[0].ServiceAccountName not found or incorrect")
				}
			},
		},
		{
			name:          "JSON_NoMetadata",
			formatterType: TypeJSON,
			opts:          optsNoMeta,
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := json.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal JSON output: %v. Output:\n%s", err, output)
				}
				if data.Metadata != nil {
					t.Errorf("JSON output without metadata: Metadata field is not nil, got %+v", data.Metadata)
				}
				if len(data.RBACData) == 0 || data.RBACData[0].ServiceAccountName != "sa1" {
					t.Errorf("JSON RBACData[0].ServiceAccountName not found or incorrect (no metadata)")
				}
			},
		},
		// YAML Formatter Tests
		{
			name:          "YAML_WithMetadata",
			formatterType: TypeYAML,
			opts:          optsWithMeta,
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := yaml.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal YAML output: %v. Output:\n%s", err, output)
				}
				if data.Metadata == nil {
					t.Fatal("YAML output with metadata: Metadata field is nil")
				}
				if data.Metadata.Name != "test-app" {
					t.Errorf("YAML Metadata.Name got %s, want test-app", data.Metadata.Name)
				}
				if len(data.RBACData) == 0 || data.RBACData[0].ServiceAccountName != "sa1" {
					t.Errorf("YAML RBACData[0].ServiceAccountName not found or incorrect")
				}
			},
		},
		{
			name:          "YAML_NoMetadata",
			formatterType: TypeYAML,
			opts:          optsNoMeta,
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := yaml.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal YAML output: %v. Output:\n%s", err, output)
				}
				if data.Metadata != nil {
					t.Errorf("YAML output without metadata: Metadata field is not nil, got %+v", data.Metadata)
				}
				if len(data.RBACData) == 0 || data.RBACData[0].ServiceAccountName != "sa1" {
					t.Errorf("YAML RBACData[0].ServiceAccountName not found or incorrect (no metadata)")
				}
			},
		},
		// Table Formatter Tests
		{
			name:          "Table_WithMetadata",
			formatterType: TypeTable,
			opts:          optsWithMeta, // buildTables itself uses these opts for PrepareData
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				// Metadata table itself is always rendered by buildTables from raw types.Result.
				// opts.IncludeMetadata affects what PrepareData (called by buildTables for other tables) includes.
				if !strings.Contains(output, "test-app") {
					t.Errorf("Table output missing metadata Name 'test-app'")
				}
				if !strings.Contains(output, "sa1") || !strings.Contains(output, "pod-reader") {
					t.Errorf("Table output missing key data elements 'sa1' or 'pod-reader'")
				}
			},
		},
		{
			name:          "Table_NoMetadata_EffectOnSubTables",
			formatterType: TypeTable,
			opts:          optsNoMeta, // This should mean PrepareData (in buildTables) omits metadata
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				// The main metadata table from buildTables might still show basic info from types.Result.
				// The effect of optsNoMeta is that ParsedData.Metadata (used by buildTables for sub-tables) will be nil.
				// For tables, the most direct check is that the output is generated.
				// A truly deep check would involve parsing the table output.
				if !strings.Contains(output, "sa1") || !strings.Contains(output, "pod-reader") {
					t.Errorf("Table output (no metadata for sub-tables) missing key data elements 'sa1' or 'pod-reader'")
				}
				// Check for absence of metadata *within the ParsedData sections* is harder without parsing table.
				// We trust PrepareData's own tests for correctly omitting Metadata field in ParsedData.
			},
		},
		// Markdown Formatter Tests
		{
			name:          "Markdown_WithMetadata",
			formatterType: TypeMarkdown,
			opts:          optsWithMeta,
			expectedError: false,
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "test-app") {
					t.Errorf("Markdown output missing metadata Name 'test-app'")
				}
				if !strings.Contains(output, "sa1") || !strings.Contains(output, "pod-reader") {
					t.Errorf("Markdown output missing key data elements 'sa1' or 'pod-reader'")
				}
				// Specific markdown table check for the Name row in the Metadata table
				// Based on observed output: | NAME | test-app |
				if !strings.Contains(output, "| NAME | test-app |") {
					t.Logf("Markdown output for metadata table:\n%s", output)
					t.Errorf("Markdown output for 'NAME | test-app' row not found as expected in metadata table")
				}
			},
		},
		// Error cases for JSON and YAML marshaling
		{
			name:          "JSON_MarshalError",
			formatterType: TypeJSON,
			opts:          optsWithMeta,
			expectedError: true,
			checkOutput: func(t *testing.T, output string) {
				// This should not be called since we expect an error
				t.Error("checkOutput called when error was expected")
			},
			getTestData: func() types.Result {
				return getTestResultData("JSON_MarshalError")
			},
		},
		// {
		// 	name:          "YAML_MarshalPanic",
		// 	formatterType: TypeYAML,
		// 	opts:          optsWithMeta,
		// 	expectedError: true,
		// 	checkOutput: func(t *testing.T, output string) {
		// 		// This should not be called since we expect an error
		// 		t.Error("checkOutput called when error was expected")
		// 	},
		// 	getTestData: func() types.Result {
		// 		return getTestResultData("YAML_MarshalPanic")
		// 	},
		// },
		{
			name:          "YAML_MarshalError",
			formatterType: TypeYAML,
			opts:          optsWithMeta,
			expectedError: true,
			checkOutput: func(t *testing.T, output string) {
				// This should not be called since we expect an error
				t.Error("checkOutput called when error was expected")
			},
			getTestData: func() types.Result {
				return getTestResultData("YAML_MarshalError")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formatter, err := NewFormatter(tc.formatterType, tc.opts)
			if err != nil {
				t.Fatalf("NewFormatter failed: %v", err)
			}

			// Use case-specific test data if provided, otherwise use default
			data := testData
			if tc.getTestData != nil {
				data = tc.getTestData()
			}
			output, err := formatter.Format(data)

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected an error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if tc.checkOutput != nil {
					tc.checkOutput(t, output)
				}
				if output == "" {
					t.Errorf("Expected output, but got empty string")
				}
			}
		})
	}

	// Test error from PrepareData propagation
	t.Run("JSON_PrepareDataError", func(t *testing.T) {
		formatter, _ := NewFormatter(TypeJSON, DefaultOptions())
		badData := types.Result{IdentityData: &types.ExtractedData{Data: map[string]interface{}{"identities": "not-a-map"}}}
		_, err := formatter.Format(badData)
		if err == nil {
			t.Error("Expected error from PrepareData, got nil")
		} else if !strings.Contains(err.Error(), "invalid Identity data format") {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("YAML_PrepareDataError", func(t *testing.T) {
		formatter, _ := NewFormatter(TypeYAML, DefaultOptions())
		badData := types.Result{RBACData: &types.ExtractedData{Data: map[string]interface{}{"rbac": "not-a-map"}}}
		_, err := formatter.Format(badData)
		if err == nil {
			t.Error("Expected error from PrepareData, got nil")
		} else if !strings.Contains(err.Error(), "invalid RBAC data format") {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("Table_PrepareDataError", func(t *testing.T) {
		// This test assumes buildTables calls PrepareData and propagates its error.
		// If buildTables handles errors from PrepareData differently, this test might need adjustment.
		formatter, _ := NewFormatter(TypeTable, DefaultOptions())
		// Using WorkloadData for a unique error message source for this test
		badData := types.Result{WorkloadData: &types.ExtractedData{Data: map[string]interface{}{"workloads": "not-a-map"}}}
		_, err := formatter.Format(badData)
		if err == nil {
			t.Error("Expected error from PrepareData (via buildTables), got nil")
		} else if !strings.Contains(err.Error(), "invalid Workload data format") {
			// This error comes from PrepareData
			t.Errorf("Unexpected error message: %s, expected 'invalid Workload data format'", err.Error())
		}
	})

	t.Run("Markdown_PrepareDataError", func(t *testing.T) {
		formatter, _ := NewFormatter(TypeMarkdown, DefaultOptions())
		badData := types.Result{IdentityData: &types.ExtractedData{Data: map[string]interface{}{"identities": "not-a-map-for-markdown"}}}
		_, err := formatter.Format(badData)
		if err == nil {
			t.Error("Expected error from PrepareData (via buildTables), got nil")
		} else if !strings.Contains(err.Error(), "invalid Identity data format") {
			// This error comes from PrepareData
			t.Errorf("Unexpected error message: %s, expected 'invalid Identity data format'", err.Error())
		}
	})
}
