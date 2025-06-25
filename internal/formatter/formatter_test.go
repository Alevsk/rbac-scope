package formatter

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/logger"
	"github.com/alevsk/rbac-ops/internal/policyevaluation"
	"github.com/alevsk/rbac-ops/internal/types"
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
	extraData := make(map[string]interface{}) // Ensure Extra is initialized

	return types.Result{
		Name:         name,
		Version:      version,
		Source:       source,
		Timestamp:    ts,
		IdentityData: &types.ExtractedData{Data: identityData},
		RBACData:     &types.ExtractedData{Data: rbacData},
		WorkloadData: &types.ExtractedData{Data: workloadData},
		Extra:        extraData, // Add Extra here
	}
}

func newTestResultWithHelm(name, version, source string, ts int64, chartAPIVersion, chartName, chartVersion string) types.Result {
	res := newTestResult(name, version, source, ts) // newTestResult now initializes Extra
	res.Extra["helm"] = map[string]interface{}{
		"apiVersion": chartAPIVersion,
		"name":       chartName,
		"version":    chartVersion,
	}
	return res
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
			name: "empty result with helm metadata",
			inputRes: func(ts int64) types.Result {
				return newTestResultWithHelm("helm-empty", "v0.1", "helm-src", ts, "v2", "my-chart", "0.1.0")
			},
			inputOpts: DefaultOptions(),
			wantParsed: ParsedData{
				Metadata: &Metadata{
					Name:            "helm-empty",
					Version:         "v0.1",
					Source:          "helm-src",
					Timestamp:       timestamp,
					ChartAPIVersion: "v2",
					ChartName:       "my-chart",
					ChartVersion:    "0.1.0",
					Extra: map[string]interface{}{
						"helm": map[string]interface{}{
							"apiVersion": "v2",
							"name":       "my-chart",
							"version":    "0.1.0",
						},
					},
				},
				IdentityData: []SAIdentityEntry{},
				RBACData:     []SARoleBindingEntry{},
				WorkloadData: []SAWorkloadEntry{},
			},
		},
		{
			name: "result with partial helm metadata",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("helm-partial", "v0.2", "helm-src-partial", ts)
				res.Extra["helm"] = map[string]interface{}{
					"name": "only-name-chart",
				}
				return res
			},
			inputOpts: DefaultOptions(),
			wantParsed: ParsedData{
				Metadata: &Metadata{
					Name:      "helm-partial",
					Version:   "v0.2",
					Source:    "helm-src-partial",
					Timestamp: timestamp,
					ChartName: "only-name-chart",
					Extra: map[string]interface{}{
						"helm": map[string]interface{}{
							"name": "only-name-chart",
						},
					},
				},
				IdentityData: []SAIdentityEntry{},
				RBACData:     []SARoleBindingEntry{},
				WorkloadData: []SAWorkloadEntry{},
			},
		},
		{
			name: "result with invalid helm metadata type",
			inputRes: func(ts int64) types.Result {
				res := newTestResult("helm-invalid", "v0.3", "helm-src-invalid", ts)
				res.Extra["helm"] = "not-a-map" // Invalid type
				return res
			},
			inputOpts: DefaultOptions(),
			wantParsed: ParsedData{
				Metadata: &Metadata{
					Name:      "helm-invalid",
					Version:   "v0.3",
					Source:    "helm-src-invalid",
					Timestamp: timestamp,
					Extra: map[string]interface{}{ // Extra still contains the invalid helm data
						"helm": "not-a-map",
					},
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
					Extra:     map[string]interface{}{}, // Expect empty map instead of nil
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
						RiskRules:          []int64{9996},
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
						RiskRules:          []int64{9996},
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
				if len(entry.RiskRules) == 0 {
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
				tc.checkFunc(t, parsed, tc.wantParsed)
			} else {
				if diff := cmp.Diff(tc.wantParsed, parsed, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("PrepareData() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func getTestResultData(testCase string) types.Result {
	timestamp := time.Now().Unix()
	var res types.Result

	switch testCase {
	case "JSON_MarshalError":
		res = newTestResult("test-app", "v1.0", "test-src", timestamp)
		circular := make(map[string]interface{})
		circular["self"] = circular
		res.Extra = circular
	case "YAML_MarshalPanic":
		res = newTestResult("test-app", "v1.0", "test-src", timestamp)
		res.Extra = map[string]interface{}{"fn": func() {}}
	case "YAML_MarshalError":
		res = newTestResult("test-app", "v1.0", "test-src", timestamp)
		res.Extra = map[string]interface{}{"ch": make(chan int)}
	case "WithHelm":
		res = newTestResultWithHelm("helm-app", "v1.1", "helm-src", timestamp, "v2", "my-helm-chart", "1.2.3")
	default:
		res = newTestResult("test-app", "v1.0", "test-src", timestamp)
	}

	if testCase != "JSON_MarshalError" && testCase != "YAML_MarshalPanic" && testCase != "YAML_MarshalError" {
		addRawIdentityData(&res, "sa1", "ns1", extractor.Identity{Name: "sa1", Namespace: "ns1", AutomountToken: true, Secrets: []string{"s1"}, ImagePullSecrets: []string{"ips1"}})
		saRBACEntryData := extractor.ServiceAccountRBAC{
			Roles: []extractor.RBACRole{
				{Type: "Role", Name: "pod-reader", Namespace: "ns1", Permissions: extractor.RuleApiGroup{"": extractor.RuleResource{"pods": extractor.RuleResourceName{"my-pod": extractor.RuleVerb{"get": {}, "list": {}}}}}},
			},
		}
		addRawRBACData(&res, "sa1", "ns1", saRBACEntryData)
		addRawWorkloadData(&res, []extractor.Workload{{Type: "Deployment", Name: "app-dep", Namespace: "ns1", ServiceAccount: "sa1", Containers: []extractor.Container{{Name: "main", Image: "app-image"}}}})
	}
	return res
}

func TestFormatters(t *testing.T) {
	optsWithMeta := DefaultOptions()
	optsNoMeta := &Options{IncludeMetadata: false}

	testCases := []struct {
		name          string
		formatterType Type
		opts          *Options
		expectedError bool
		checkOutput   func(t *testing.T, output string)
		getTestData   func() types.Result
	}{
		{
			name:          "JSON_WithMetadata",
			formatterType: TypeJSON,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := json.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v. Output: %s", err, output)
				}
				if data.Metadata == nil || data.Metadata.Name != "test-app" || data.Metadata.ChartName != "" {
					t.Errorf("JSON_WithMetadata check failed. Metadata: %+v", data.Metadata)
				}
				if len(data.RBACData) == 0 || data.RBACData[0].ServiceAccountName != "sa1" {
					t.Error("JSON_WithMetadata RBAC check failed")
				}
			},
		},
		{
			name:          "JSON_WithHelmMetadata",
			formatterType: TypeJSON,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("WithHelm") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := json.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal JSON (Helm): %v. Output: %s", err, output)
				}
				if data.Metadata == nil || data.Metadata.Name != "helm-app" ||
					data.Metadata.ChartName != "my-helm-chart" || data.Metadata.ChartAPIVersion != "v2" || data.Metadata.ChartVersion != "1.2.3" {
					t.Errorf("JSON_WithHelmMetadata check failed. Metadata: %+v", data.Metadata)
				}
			},
		},
		{
			name:          "JSON_NoMetadata",
			formatterType: TypeJSON,
			opts:          optsNoMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := json.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal JSON (NoMeta): %v. Output: %s", err, output)
				}
				if data.Metadata != nil {
					t.Errorf("JSON_NoMetadata check failed, metadata not nil. Metadata: %+v", data.Metadata)
				}
			},
		},
		{
			name:          "YAML_WithMetadata",
			formatterType: TypeYAML,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := yaml.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal YAML: %v. Output: %s", err, output)
				}
				if data.Metadata == nil || data.Metadata.Name != "test-app" || data.Metadata.ChartName != "" {
					t.Errorf("YAML_WithMetadata check failed. Metadata: %+v", data.Metadata)
				}
			},
		},
		{
			name:          "YAML_WithHelmMetadata",
			formatterType: TypeYAML,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("WithHelm") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := yaml.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal YAML (Helm): %v. Output: %s", err, output)
				}
				if data.Metadata == nil || data.Metadata.Name != "helm-app" ||
					data.Metadata.ChartName != "my-helm-chart" || data.Metadata.ChartAPIVersion != "v2" || data.Metadata.ChartVersion != "1.2.3" {
					t.Errorf("YAML_WithHelmMetadata check failed. Metadata: %+v", data.Metadata)
				}
			},
		},
		{
			name:          "YAML_NoMetadata",
			formatterType: TypeYAML,
			opts:          optsNoMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				var data ParsedData
				if err := yaml.Unmarshal([]byte(output), &data); err != nil {
					t.Fatalf("Failed to unmarshal YAML (NoMeta): %v. Output: %s", err, output)
				}
				if data.Metadata != nil {
					t.Errorf("YAML_NoMetadata check failed, metadata not nil. Metadata: %+v", data.Metadata)
				}
			},
		},
		{
			name:          "Table_WithMetadata",
			formatterType: TypeTable,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "test-app") || strings.Contains(output, "CHART NAME") ||
					!strings.Contains(output, "sa1") || !strings.Contains(output, "pod-reader") {
					t.Errorf("Table_WithMetadata check failed. Output: %s", output)
				}
			},
		},
		{
			name:          "Table_WithHelmMetadata",
			formatterType: TypeTable,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("WithHelm") },
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "helm-app") || !strings.Contains(output, "CHART API VERSION") || !strings.Contains(output, "v2") ||
					!strings.Contains(output, "CHART NAME") || !strings.Contains(output, "my-helm-chart") ||
					!strings.Contains(output, "CHART VERSION") || !strings.Contains(output, "1.2.3") {
					t.Errorf("Table_WithHelmMetadata check failed. Output: %s", output)
				}
			},
		},
		{
			name:          "Markdown_WithMetadata",
			formatterType: TypeMarkdown,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("") },
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "| NAME | test-app |") || strings.Contains(output, "| CHART NAME |") ||
					!strings.Contains(output, "sa1") || !strings.Contains(output, "pod-reader") {
					t.Errorf("Markdown_WithMetadata check failed. Output: %s", output)
				}
			},
		},
		{
			name:          "Markdown_WithHelmMetadata",
			formatterType: TypeMarkdown,
			opts:          optsWithMeta,
			getTestData:   func() types.Result { return getTestResultData("WithHelm") },
			checkOutput: func(t *testing.T, output string) {
				if !strings.Contains(output, "| NAME | helm-app |") ||
					!strings.Contains(output, "| CHART API VERSION | v2 |") ||
					!strings.Contains(output, "| CHART NAME | my-helm-chart |") ||
					!strings.Contains(output, "| CHART VERSION | 1.2.3 |") {
					t.Errorf("Markdown_WithHelmMetadata check failed. Output: %s", output)
				}
			},
		},
		{name: "JSON_MarshalError", formatterType: TypeJSON, opts: optsWithMeta, expectedError: true, getTestData: func() types.Result { return getTestResultData("JSON_MarshalError") }},
		{name: "YAML_MarshalError", formatterType: TypeYAML, opts: optsWithMeta, expectedError: true, getTestData: func() types.Result { return getTestResultData("YAML_MarshalError") }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			formatter, err := NewFormatter(tc.formatterType, tc.opts)
			if err != nil {
				t.Fatalf("NewFormatter failed: %v", err)
			}

			dataToFormat := getTestResultData("") // Default
			if tc.getTestData != nil {
				dataToFormat = tc.getTestData()
			}

			output, err := formatter.Format(dataToFormat)

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected an error, but got nil. Output: %s", output)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, but got: %v", err)
				}
				if tc.checkOutput != nil {
					tc.checkOutput(t, output)
				}
				if output == "" { // Output can be empty if data is empty, but not for these tests
					t.Errorf("Expected output, but got empty string")
				}
			}
		})
	}

	t.Run("JSON_PrepareDataError", func(t *testing.T) {
		formatter, _ := NewFormatter(TypeJSON, DefaultOptions())
		badData := types.Result{IdentityData: &types.ExtractedData{Data: map[string]interface{}{"identities": "not-a-map"}}}
		_, err := formatter.Format(badData)
		if err == nil || !strings.Contains(err.Error(), "invalid Identity data format") {
			t.Errorf("JSON_PrepareDataError failed: %v", err)
		}
	})

	t.Run("YAML_PrepareDataError", func(t *testing.T) {
		formatter, _ := NewFormatter(TypeYAML, DefaultOptions())
		badData := types.Result{RBACData: &types.ExtractedData{Data: map[string]interface{}{"rbac": "not-a-map"}}}
		_, err := formatter.Format(badData)
		if err == nil || !strings.Contains(err.Error(), "invalid RBAC data format") {
			t.Errorf("YAML_PrepareDataError failed: %v", err)
		}
	})

	t.Run("Table_BuildTablesError", func(t *testing.T) { // Renamed to reflect buildTables
		formatter, _ := NewFormatter(TypeTable, DefaultOptions())
		badData := types.Result{WorkloadData: &types.ExtractedData{Data: map[string]interface{}{"workloads": "not-a-map"}}}
		_, err := formatter.Format(badData) // Format calls buildTables
		if err == nil || !strings.Contains(err.Error(), "invalid Workload data format") {
			t.Errorf("Table_BuildTablesError failed: %v", err)
		}
	})

	t.Run("Markdown_BuildTablesError", func(t *testing.T) { // Renamed to reflect buildTables
		formatter, _ := NewFormatter(TypeMarkdown, DefaultOptions())
		badData := types.Result{IdentityData: &types.ExtractedData{Data: map[string]interface{}{"identities": "not-a-map"}}}
		_, err := formatter.Format(badData) // Format calls buildTables
		if err == nil || !strings.Contains(err.Error(), "invalid Identity data format") {
			t.Errorf("Markdown_BuildTablesError failed: %v", err)
		}
	})
}
