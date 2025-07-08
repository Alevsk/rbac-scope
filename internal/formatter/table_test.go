package formatter

import (
	"strings"
	"testing"
	"time"

	"github.com/alevsk/rbac-scope/internal/extractor"
	"github.com/alevsk/rbac-scope/internal/types"
	"github.com/jedib0t/go-pretty/v6/table"
	// "github.com/stretchr/testify/assert" // Using standard library for assertions for now
)

// Helper to create a basic types.Result for table tests
func newTableTestResult(name, version, source string, ts int64) types.Result {
	return types.Result{
		Name:         name,
		Version:      version,
		Source:       source,
		Timestamp:    ts,
		IdentityData: &types.ExtractedData{Data: make(map[string]interface{})},
		RBACData:     &types.ExtractedData{Data: make(map[string]interface{})},
		WorkloadData: &types.ExtractedData{Data: make(map[string]interface{})},
	}
}

// Helper to add identity data for full tests
func addTableTestIdentity(res *types.Result, saName, saNamespace string, automount bool, secrets, imgPullSecrets []string) {
	idMap, _ := res.IdentityData.Data["identities"].(map[string]map[string]extractor.Identity)
	if _, ok := idMap[saName]; !ok {
		idMap[saName] = make(map[string]extractor.Identity)
	}
	idMap[saName][saNamespace] = extractor.Identity{
		Name:             saName,
		Namespace:        saNamespace,
		AutomountToken:   automount,
		Secrets:          secrets,
		ImagePullSecrets: imgPullSecrets,
	}
}

// Helper to add RBAC data for full tests
func addTableTestRBAC(res *types.Result, saName, saNamespace string, roles []extractor.RBACRole) {
	rbacMap, _ := res.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
	if _, ok := rbacMap[saName]; !ok {
		rbacMap[saName] = make(map[string]extractor.ServiceAccountRBAC)
	}
	currentRBAC := rbacMap[saName][saNamespace]
	currentRBAC.Roles = append(currentRBAC.Roles, roles...)
	rbacMap[saName][saNamespace] = currentRBAC
}

// Helper to add workload data for full tests
func addTableTestWorkload(res *types.Result, saName, saNamespace string, workloadType, workloadName, containerName, imageName string) {
	wlMap, _ := res.WorkloadData.Data["workloads"].(map[string]map[string][]extractor.Workload)
	if _, ok := wlMap[saName]; !ok {
		wlMap[saName] = make(map[string][]extractor.Workload)
	}
	wlMap[saName][saNamespace] = append(wlMap[saName][saNamespace], extractor.Workload{
		Type:           extractor.WorkloadType(workloadType),
		Name:           workloadName,
		Namespace:      saNamespace,
		ServiceAccount: saName,
		Containers:     []extractor.Container{{Name: containerName, Image: imageName}},
	})
}

func TestBuildTables_FullData(t *testing.T) {
	timestamp := time.Now().Unix()
	fullDataRes := newTableTestResult("complex-app", "v1.2.3", "full-src", timestamp)
	// Ensure maps are initialized correctly
	fullDataRes.IdentityData.Data["identities"] = make(map[string]map[string]extractor.Identity)
	fullDataRes.RBACData.Data["rbac"] = make(map[string]map[string]extractor.ServiceAccountRBAC)
	fullDataRes.WorkloadData.Data["workloads"] = make(map[string]map[string][]extractor.Workload)

	// Populate with data
	addTableTestIdentity(&fullDataRes, "sa-data", "prod", true, []string{"secret-token"}, []string{"regcred"})
	addTableTestRBAC(&fullDataRes, "sa-data", "prod", []extractor.RBACRole{
		{Type: "Role", Name: "config-reader", Namespace: "prod", Permissions: extractor.RuleApiGroup{
			"": {"configmaps": {"": {"get": {}, "list": {}}}},
		}},
	})
	addTableTestRBAC(&fullDataRes, "sa-admin", "kube-system", []extractor.RBACRole{
		{Type: "ClusterRole", Name: "cluster-admin-dangerous", Namespace: "*", Permissions: extractor.RuleApiGroup{
			"*": {"*": {"*": {"*": {}}}}, // Critical permission
		}},
	})
	addTableTestWorkload(&fullDataRes, "sa-data", "prod", "Deployment", "data-processor", "main-proc", "processor:latest")

	mt, it, rt, pat, wt, err := buildTables(fullDataRes)
	if err != nil {
		t.Fatalf("buildTables() with full data returned error: %v", err)
	}

	// Basic nil checks
	if mt == nil || it == nil || rt == nil || pat == nil || wt == nil {
		t.Fatal("One or more tables are nil for full data test")
	}

	// Check Metadata
	mtRendered := renderTableForTest(mt)
	if !strings.Contains(mtRendered, "complex-app") {
		t.Error("Metadata table missing Name 'complex-app'")
	}

	// Check Identity Table
	itRendered := renderTableForTest(it)
	if !strings.Contains(itRendered, "sa-data") {
		t.Error("Identity table missing 'sa-data'")
	}
	if !strings.Contains(itRendered, "prod") {
		t.Error("Identity table missing 'prod' namespace for sa-data")
	}
	if !strings.Contains(itRendered, "true") {
		t.Error("Identity table missing automountToken 'true' for sa-data")
	} // Assuming 'true' is rendered for bool
	if !strings.Contains(itRendered, "secret-token") {
		t.Error("Identity table missing 'secret-token'")
	}
	if it.Length() != 1 {
		t.Errorf("IdentityTable expected 1 row, got %d", it.Length())
	}

	// Check RBAC Table
	rtRendered := renderTableForTest(rt)
	if !strings.Contains(rtRendered, "sa-data") {
		t.Error("RBAC table missing 'sa-data'")
	}
	if !strings.Contains(rtRendered, "config-reader") {
		t.Error("RBAC table missing 'config-reader' role")
	}
	if !strings.Contains(rtRendered, "configmaps") {
		t.Error("RBAC table missing 'configmaps' resource")
	}
	if !strings.Contains(rtRendered, "get,list") && !strings.Contains(rtRendered, "list,get") {
		t.Error("RBAC table missing 'get,list' verbs for configmaps")
	}
	if !strings.Contains(rtRendered, "Low") {
		t.Error("RBAC table missing 'Low' risk for sa-data/config-reader")
	}

	if !strings.Contains(rtRendered, "sa-admin") {
		t.Error("RBAC table missing 'sa-admin'")
	}
	if !strings.Contains(rtRendered, "cluster-admin-dangerous") {
		t.Error("RBAC table missing 'cluster-admin-dangerous' role")
	}
	if !strings.Contains(rtRendered, "Critical") {
		t.Error("RBAC table missing 'Critical' risk for sa-admin/cluster-admin-dangerous")
	}
	if rt.Length() != 2 {
		t.Errorf("RBACTable expected 2 rows, got %d", rt.Length())
	}

	// Check Potential Abuse Table
	// This table's content is dynamic based on policyevaluation.
	// We expect entries for the "cluster-admin-dangerous" role.
	patRendered := renderTableForTest(pat)
	if strings.Contains(rtRendered, "Critical") && !strings.Contains(patRendered, "sa-admin") {
		t.Error("PotentialAbuseTable missing entries for 'sa-admin' which has Critical permissions")
	}
	// A more specific check could be for a known high-risk action name if predictable from policyevaluation
	// For example: if !strings.Contains(patRendered, "Wildcard permission on all resources cluster-wide") { ... }
	// For now, ensuring it's not empty if critical permissions exist is a good start.
	if strings.Contains(rtRendered, "Critical") && pat.Length() == 0 {
		t.Error("PotentialAbuseTable is empty but critical permissions were found in RBAC table")
	}

	// Check Workload Table
	wtRendered := renderTableForTest(wt)
	if !strings.Contains(wtRendered, "sa-data") {
		t.Error("Workload table missing 'sa-data'")
	}
	if !strings.Contains(wtRendered, "Deployment") {
		t.Error("Workload table missing 'Deployment' type")
	}
	if !strings.Contains(wtRendered, "data-processor") {
		t.Error("Workload table missing 'data-processor' name")
	}
	if !strings.Contains(wtRendered, "processor:latest") {
		t.Error("Workload table missing 'processor:latest' image")
	}
	if wt.Length() != 1 {
		t.Errorf("WorkloadTable expected 1 row, got %d", wt.Length())
	}

}

// Helper to render a table to a string for assertion.
// Note: table.Render() typically writes to an io.Writer. For tests,
// if we need to capture string output without side effects, we'd usually
// set an output mirror to a bytes.Buffer. However, go-pretty's Render()
// also returns the string directly, which is convenient here.
func renderTableForTest(tb table.Writer) string {
	return tb.Render()
}

func TestBuildTables_EmptyResult(t *testing.T) {
	timestamp := time.Now().Unix()
	emptyData := newTableTestResult("empty-app", "v0.0.1", "test-src", timestamp)
	// Ensure the map keys exist, even if empty, as expected by buildTables
	emptyData.IdentityData.Data["identities"] = make(map[string]map[string]extractor.Identity)
	emptyData.RBACData.Data["rbac"] = make(map[string]map[string]extractor.ServiceAccountRBAC)
	emptyData.WorkloadData.Data["workloads"] = make(map[string]map[string][]extractor.Workload)

	mt, it, rt, pat, wt, err := buildTables(emptyData)

	if err != nil {
		t.Fatalf("buildTables() with empty data returned error: %v", err)
	}

	if mt == nil {
		t.Error("MetadataTable is nil")
	}
	if it == nil {
		t.Error("IdentityTable is nil")
	}
	if rt == nil {
		t.Error("RBACTable is nil")
	}
	if pat == nil {
		t.Error("PotentialAbuseTable is nil")
	}
	if wt == nil {
		t.Error("WorkloadTable is nil")
	}

	// Check titles
	if mt != nil && !strings.Contains(renderTableForTest(mt), "METADATA") {
		t.Errorf("MetadataTable missing title 'METADATA'. Got: %s", renderTableForTest(mt))
	}
	if it != nil && !strings.Contains(renderTableForTest(it), "SERVICE ACCOUNT IDENTITIES") {
		t.Errorf("IdentityTable missing title 'SERVICE ACCOUNT IDENTITIES'. Got: %s", renderTableForTest(it))
	}
	if rt != nil && !strings.Contains(renderTableForTest(rt), "SERVICE ACCOUNT BINDINGS") {
		t.Errorf("RBACTable missing title 'SERVICE ACCOUNT BINDINGS'. Got: %s", renderTableForTest(rt))
	}
	if pat != nil && !strings.Contains(renderTableForTest(pat), "POTENTIAL ABUSE") {
		t.Errorf("PotentialAbuseTable missing title 'POTENTIAL ABUSE'. Got: %s", renderTableForTest(pat))
	}
	if wt != nil && !strings.Contains(renderTableForTest(wt), "SERVICE ACCOUNT WORKLOADS") {
		t.Errorf("WorkloadTable missing title 'SERVICE ACCOUNT WORKLOADS'. Got: %s", renderTableForTest(wt))
	}

	// Check metadata content
	if mt != nil {
		mtRendered := renderTableForTest(mt)
		if !strings.Contains(mtRendered, "empty-app") {
			t.Errorf("MetadataTable missing Name. Got: %s", mtRendered)
		}
		if !strings.Contains(mtRendered, "v0.0.1") {
			t.Errorf("MetadataTable missing Version. Got: %s", mtRendered)
		}
		if !strings.Contains(mtRendered, "test-src") {
			t.Errorf("MetadataTable missing Source. Got: %s", mtRendered)
		}
	}

	// Check row counts for data tables (should be 0 for empty result)
	if it != nil && it.Length() != 0 {
		t.Errorf("IdentityTable expected 0 rows for empty data, got %d", it.Length())
	}
	if rt != nil && rt.Length() != 0 {
		t.Errorf("RBACTable expected 0 rows for empty data, got %d", rt.Length())
	}
	if pat != nil && pat.Length() != 0 {
		t.Errorf("PotentialAbuseTable expected 0 rows for empty data, got %d", pat.Length())
	}
	if wt != nil && wt.Length() != 0 {
		t.Errorf("WorkloadTable expected 0 rows for empty data, got %d", wt.Length())
	}
}

func TestBuildTables_InvalidDataFormat(t *testing.T) {
	baseResult := newTableTestResult("test", "v1", "src", time.Now().Unix())
	// Ensure base maps are initialized so we only test one failure at a time
	baseResult.IdentityData.Data["identities"] = make(map[string]map[string]extractor.Identity)
	baseResult.RBACData.Data["rbac"] = make(map[string]map[string]extractor.ServiceAccountRBAC)
	baseResult.WorkloadData.Data["workloads"] = make(map[string]map[string][]extractor.Workload)

	tests := []struct {
		name        string
		setupResult func() types.Result
		wantErrMsg  string
	}{
		{
			name: "invalid identity data format",
			setupResult: func() types.Result {
				res := baseResult
				res.IdentityData.Data["identities"] = "not-a-map" // Invalid format
				return res
			},
			wantErrMsg: "invalid Identity data format",
		},
		{
			name: "invalid rbac data format",
			setupResult: func() types.Result {
				res := baseResult
				// Reset identity to valid default for this test case
				res.IdentityData.Data["identities"] = make(map[string]map[string]extractor.Identity)
				res.RBACData.Data["rbac"] = "not-a-map" // Invalid format
				return res
			},
			wantErrMsg: "invalid RBAC data format",
		},
		{
			name: "invalid workload data format",
			setupResult: func() types.Result {
				res := baseResult
				// Reset identity and rbac to valid defaults for this test case
				res.IdentityData.Data["identities"] = make(map[string]map[string]extractor.Identity)
				res.RBACData.Data["rbac"] = make(map[string]map[string]extractor.ServiceAccountRBAC)
				res.WorkloadData.Data["workloads"] = "not-a-map" // Invalid format
				return res
			},
			wantErrMsg: "invalid Workload data format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := tt.setupResult()
			_, _, _, _, _, err := buildTables(inputData)

			if err == nil {
				t.Fatalf("buildTables() expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("buildTables() error = %q, want error containing %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}
