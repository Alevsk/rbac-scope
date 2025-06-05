package formatter

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/policyevaluation"
	"github.com/alevsk/rbac-ops/internal/types"
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
		if entries[i].ServiceAccountName != entries[j].ServiceAccountName { return entries[i].ServiceAccountName < entries[j].ServiceAccountName }
		if entries[i].Namespace != entries[j].Namespace { return entries[i].Namespace < entries[j].Namespace }
		if entries[i].RoleType != entries[j].RoleType { return entries[i].RoleType < entries[j].RoleType }
		if entries[i].RoleName != entries[j].RoleName { return entries[i].RoleName < entries[j].RoleName }
		if entries[i].APIGroup != entries[j].APIGroup { return entries[i].APIGroup < entries[j].APIGroup }
		if entries[i].Resource != entries[j].Resource { return entries[i].Resource < entries[j].Resource }
		verbI := strings.Join(entries[i].Verbs, ",")
		verbJ := strings.Join(entries[j].Verbs, ",")
		if verbI != verbJ { return verbI < verbJ }
		return entries[i].RiskLevel < entries[j].RiskLevel
	})
}

func TestPrepareData(t *testing.T) {
	timestamp := time.Now().Unix()

	t.Run("emptyResult", func(t *testing.T) {
		res := newTestResult("empty", "v0", "src", timestamp)
		opts := DefaultOptions()
		parsed, err := PrepareData(res, opts)
		if err != nil {
			t.Fatalf("PrepareData returned error: %v", err)
		}
		if parsed.Metadata == nil && opts.IncludeMetadata {
			t.Errorf("Metadata is nil, want non-nil with default options")
		} else if parsed.Metadata != nil && !opts.IncludeMetadata {
			t.Errorf("Metadata is non-nil, want nil with IncludeMetadata=false")
		}
		if len(parsed.IdentityData) != 0 {
			t.Errorf("IdentityData not empty, got %d items", len(parsed.IdentityData))
		}
		if len(parsed.RBACData) != 0 {
			t.Errorf("RBACData not empty, got %d items", len(parsed.RBACData))
		}
		if len(parsed.WorkloadData) != 0 {
			t.Errorf("WorkloadData not empty, got %d items", len(parsed.WorkloadData))
		}
	})

	t.Run("noMetadata", func(t *testing.T) {
		res := newTestResult("test", "v1", "src", timestamp)
		opts := &Options{IncludeMetadata: false}
		parsed, err := PrepareData(res, opts)
		if err != nil {
			t.Fatalf("PrepareData returned error: %v", err)
		}
		if parsed.Metadata != nil {
			t.Errorf("Metadata is not nil, want nil")
		}
	})

	t.Run("withMetadata", func(t *testing.T) {
		res := newTestResult("app", "v0.1.0", "test-source", timestamp)
		opts := DefaultOptions()
		parsed, err := PrepareData(res, opts)
		if err != nil {
			t.Fatalf("PrepareData returned error: %v", err)
		}
		if parsed.Metadata == nil {
			t.Fatal("Metadata is nil, want populated")
		}
		expectedMeta := &Metadata{Name: "app", Version: "v0.1.0", Source: "test-source", Timestamp: timestamp, Extra: res.Extra}
		if !reflect.DeepEqual(parsed.Metadata, expectedMeta) {
			t.Errorf("Metadata content mismatch: got %+v, want %+v", parsed.Metadata, expectedMeta)
		}
	})

	t.Run("fullDataWithMetadata", func(t *testing.T) {
		res := newTestResult("full-app", "v1.1", "full-src", timestamp)
		addRawIdentityData(&res, "sa1", "ns1", extractor.Identity{Name: "sa1", Namespace: "ns1", AutomountToken: true})

		saRBACEntryData := extractor.ServiceAccountRBAC{
			Roles: []extractor.RBACRole{
				{Type: "Role", Name: "role1", Namespace: "ns1", Permissions: map[string]map[string]map[string]struct{}{"": {"pods": {"get": {}, "list": {}}}}},
				{Type: "ClusterRole", Name: "clusterrole1", Namespace: "*", Permissions: map[string]map[string]map[string]struct{}{"apps": {"deployments": {"watch": {}}}}},
			},
		}
		addRawRBACData(&res, "sa1", "ns1", saRBACEntryData)
		addRawWorkloadData(&res, []extractor.Workload{
			{Type: extractor.WorkloadType("Deployment"), Name: "dep1", Namespace: "ns1", ServiceAccount: "sa1", Containers: []extractor.Container{{Name: "c1", Image: "img1"}}},
		})

		opts := DefaultOptions()
		parsed, err := PrepareData(res, opts)
		if err != nil { t.Fatalf("PrepareData returned error: %v", err) }

		if parsed.Metadata == nil { t.Fatal("Metadata is nil") }
		if parsed.Metadata.Name != "full-app" { t.Errorf("Metadata.Name got %s, want full-app", parsed.Metadata.Name) }

		if len(parsed.IdentityData) != 1 { t.Fatalf("IdentityData len got %d, want 1", len(parsed.IdentityData)) }
		expectedID := SAIdentityEntry{ServiceAccountName: "sa1", Namespace: "ns1", AutomountToken: true, Secrets: nil, ImagePullSecrets: nil}
		if !reflect.DeepEqual(parsed.IdentityData[0], expectedID) {
			t.Errorf("IdentityData[0] got %+v, want %+v", parsed.IdentityData[0], expectedID)
		}

		if len(parsed.RBACData) != 2 {
			t.Fatalf("RBACData len got %d, want 2. Got: %+v", len(parsed.RBACData), parsed.RBACData)
		}
		expectedRBACEntries := []SARoleBindingEntry{
			{ServiceAccountName: "sa1", Namespace: "ns1", RoleType: "Role", RoleName: "role1", APIGroup: "", Resource: "pods", Verbs: []string{"get", "list"}, RiskLevel: "Low", Tags: policyevaluation.RiskTags{}},
			{ServiceAccountName: "sa1", Namespace: "ns1", RoleType: "ClusterRole", RoleName: "clusterrole1", APIGroup: "apps", Resource: "deployments", Verbs: []string{"watch"}, RiskLevel: "Low", Tags: policyevaluation.RiskTags{}},
		}

		sortSARoleBindingEntries(parsed.RBACData)
		sortSARoleBindingEntries(expectedRBACEntries)

		// More granular comparison
		for i := 0; i < len(expectedRBACEntries); i++ {
			if i >= len(parsed.RBACData) {
				t.Errorf("RBACData missing entry at index %d. Want: %+v", i, expectedRBACEntries[i])
				continue
			}
			gotEntry := parsed.RBACData[i]
			wantEntry := expectedRBACEntries[i]

			if !reflect.DeepEqual(gotEntry.ServiceAccountName, wantEntry.ServiceAccountName) { t.Errorf("idx %d: ServiceAccountName mismatch: got %s, want %s", i, gotEntry.ServiceAccountName, wantEntry.ServiceAccountName) }
			if !reflect.DeepEqual(gotEntry.Namespace, wantEntry.Namespace) { t.Errorf("idx %d: Namespace mismatch: got %s, want %s", i, gotEntry.Namespace, wantEntry.Namespace) }
			if !reflect.DeepEqual(gotEntry.RoleType, wantEntry.RoleType) { t.Errorf("idx %d: RoleType mismatch: got %s, want %s", i, gotEntry.RoleType, wantEntry.RoleType) }
			if !reflect.DeepEqual(gotEntry.RoleName, wantEntry.RoleName) { t.Errorf("idx %d: RoleName mismatch: got %s, want %s", i, gotEntry.RoleName, wantEntry.RoleName) }
			if !reflect.DeepEqual(gotEntry.APIGroup, wantEntry.APIGroup) { t.Errorf("idx %d: APIGroup mismatch: got %s, want %s", i, gotEntry.APIGroup, wantEntry.APIGroup) }
			if !reflect.DeepEqual(gotEntry.Resource, wantEntry.Resource) { t.Errorf("idx %d: Resource mismatch: got %s, want %s", i, gotEntry.Resource, wantEntry.Resource) }
			if !reflect.DeepEqual(gotEntry.Verbs, wantEntry.Verbs) { t.Errorf("idx %d: Verbs mismatch: got %v, want %v", i, gotEntry.Verbs, wantEntry.Verbs) }
			if !reflect.DeepEqual(gotEntry.RiskLevel, wantEntry.RiskLevel) { t.Errorf("idx %d: RiskLevel mismatch: got %s, want %s", i, gotEntry.RiskLevel, wantEntry.RiskLevel) }
			if !reflect.DeepEqual(gotEntry.Tags, wantEntry.Tags) { t.Errorf("idx %d: Tags mismatch: got %v, want %v", i, gotEntry.Tags, wantEntry.Tags) }
		}
		// The granular checks above are now the sole source of truth for RBACData comparison in this sub-test.
		// The potentially problematic DeepEqual on the whole slice has been removed.


		if len(parsed.WorkloadData) != 1 { t.Fatalf("WorkloadData len got %d, want 1", len(parsed.WorkloadData)) }
		expectedWkld := SAWorkloadEntry{ServiceAccountName: "sa1", Namespace: "ns1", WorkloadType: "Deployment", WorkloadName: "dep1", ContainerName: "c1", Image: "img1"}
		if !reflect.DeepEqual(parsed.WorkloadData[0], expectedWkld) {
			t.Errorf("WorkloadData[0] got %+v, want %+v", parsed.WorkloadData[0], expectedWkld)
		}
	})

	t.Run("invalidIdentityDataFormat", func(t *testing.T) {
		res := newTestResult("test", "v1", "src", timestamp)
		res.IdentityData.Data["identities"] = "this is not a map"
		_, err := PrepareData(res, DefaultOptions())
		if err == nil {
			t.Fatal("PrepareData expected error for invalid identity format, got nil")
		}
		if !strings.Contains(err.Error(), "invalid Identity data format") {
			t.Errorf("Error message %q does not contain 'invalid Identity data format'", err.Error())
		}
	})

	t.Run("invalidRBACDataFormat", func(t *testing.T) {
		res := newTestResult("test", "v1", "src", timestamp)
		res.RBACData.Data["rbac"] = "this is not a map"
		_, err := PrepareData(res, DefaultOptions())
		if err == nil {
			t.Fatal("PrepareData expected error for invalid RBAC format, got nil")
		}
		if !strings.Contains(err.Error(), "invalid RBAC data format") {
			t.Errorf("Error message %q does not contain 'invalid RBAC data format'", err.Error())
		}
	})

	t.Run("invalidWorkloadDataFormat", func(t *testing.T) {
		res := newTestResult("test", "v1", "src", timestamp)
		res.WorkloadData.Data["workloads"] = "this is not a map"
		_, err := PrepareData(res, DefaultOptions())
		if err == nil {
			t.Fatal("PrepareData expected error for invalid workload format, got nil")
		}
		if !strings.Contains(err.Error(), "invalid Workload data format") {
			t.Errorf("Error message %q does not contain 'invalid Workload data format'", err.Error())
		}
	})

	t.Run("rbacDataWithRisk", func(t *testing.T) {
		res := newTestResult("risk-app", "v1", "risk-src", timestamp)
		saRBACEntry := extractor.ServiceAccountRBAC{
			Roles: []extractor.RBACRole{
				{
					Type:      "ClusterRole",
					Name:      "super-admin-role",
					Namespace: "*",
					Permissions: map[string]map[string]map[string]struct{}{
						"*": {"*": {"*": {}}},
					},
				},
			},
		}
		addRawRBACData(&res, "risk-sa", "default", saRBACEntry)

		opts := DefaultOptions()
		parsed, err := PrepareData(res, opts)
		if err != nil {
			t.Fatalf("PrepareData returned error: %v", err)
		}
		if len(parsed.RBACData) != 1 {
			t.Fatalf("RBACData len got %d, want 1. Got: %+v", len(parsed.RBACData), parsed.RBACData)
		}

		entry := parsed.RBACData[0]
		expectedRiskLevel := "Critical"
		expectedTagContent := "ClusterAdminAccess"

		if entry.RiskLevel != expectedRiskLevel {
			t.Errorf("RBACData[0].RiskLevel is %q, want %q", entry.RiskLevel, expectedRiskLevel)
		}

		foundTag := false
		for _, tag := range entry.Tags {
			if string(tag) == expectedTagContent {
				foundTag = true
				break
			}
		}
		if !foundTag {
			t.Errorf("RBACData[0].Tags = %v, did not find expected tag %q", entry.Tags, expectedTagContent)
		}
	})
}

// NOTE: Tests for Format methods, and buildTables will be added in subsequent phases.
