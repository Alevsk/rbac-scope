package formatter

import (
	// "bytes" // Removed as it's not used by renderTableForTest in its current form
	"strings"
	"testing"
	"time"

	"github.com/alevsk/rbac-ops/internal/extractor"
	"github.com/alevsk/rbac-ops/internal/types"
	"github.com/jedib0t/go-pretty/v6/table"
)

// --- Helpers for table_test.go ---

func newTableTestResult(name, version, source string, ts int64) types.Result {
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

func addRawIdentityDataForTable(res *types.Result, saName, saNamespace string, identity extractor.Identity) {
	identitiesMap := res.IdentityData.Data["identities"].(map[string]map[string]extractor.Identity)
	if _, ok := identitiesMap[saName]; !ok {
		identitiesMap[saName] = make(map[string]extractor.Identity)
	}
	identitiesMap[saName][saNamespace] = identity
}

func addRawRBACDataForTable(res *types.Result, saName, saNamespace string, rbac extractor.ServiceAccountRBAC) {
	rbacMap := res.RBACData.Data["rbac"].(map[string]map[string]extractor.ServiceAccountRBAC)
	if _, ok := rbacMap[saName]; !ok {
		rbacMap[saName] = make(map[string]extractor.ServiceAccountRBAC)
	}
	rbacMap[saName][saNamespace] = rbac
}

func addRawWorkloadDataForTable(res *types.Result, workloads []extractor.Workload) {
	workloadMap := res.WorkloadData.Data["workloads"].(map[string]map[string][]extractor.Workload)
	for _, wl := range workloads {
		if _, ok := workloadMap[wl.ServiceAccount]; !ok {
			workloadMap[wl.ServiceAccount] = make(map[string][]extractor.Workload)
		}
		workloadMap[wl.ServiceAccount][wl.Namespace] = append(workloadMap[wl.ServiceAccount][wl.Namespace], wl)
	}
}

func TestBuildTables(t *testing.T) {
	timestamp := time.Now().Unix()
	// defaultOpts := DefaultOptions() // Options might not be needed for buildTables

	t.Run("emptyResult", func(t *testing.T) {
		res := newTableTestResult("empty-app", "v0.0", "empty-src", timestamp)

		metadataTable, identityTable, rbacTable, workloadTable, err := buildTables(res) // Pass only res
		if err != nil {
			t.Fatalf("buildTables returned error: %v", err)
		}

		if metadataTable == nil {
			t.Error("metadataTable is nil")
		}
		if identityTable == nil {
			t.Error("identityTable is nil")
		}
		if rbacTable == nil {
			t.Error("rbacTable is nil")
		}
		if workloadTable == nil {
			t.Error("workloadTable is nil")
		}

		if !strings.Contains(renderTableForTest(metadataTable), "METADATA") {
			t.Error("Metadata table missing title")
		}
		if !strings.Contains(renderTableForTest(identityTable), "SERVICE ACCOUNT IDENTITIES") {
			t.Error("Identity table missing title")
		}
		if !strings.Contains(renderTableForTest(rbacTable), "SERVICE ACCOUNT BINDINGS") {
			t.Error("RBAC table missing title")
		}
		if !strings.Contains(renderTableForTest(workloadTable), "SERVICE ACCOUNT WORKLOADS") {
			t.Error("Workload table missing title")
		}

		if identityTable.Length() != 0 {
			t.Errorf("identityTable should have 0 data rows, got %d", identityTable.Length())
		}
		if rbacTable.Length() != 0 {
			t.Errorf("rbacTable should have 0 data rows, got %d", rbacTable.Length())
		}
		if workloadTable.Length() != 0 {
			t.Errorf("workloadTable should have 0 data rows, got %d", workloadTable.Length())
		}
	})

	t.Run("fullData", func(t *testing.T) {
		res := newTableTestResult("full-data-app", "v1.0", "full-data-src", timestamp)
		addRawIdentityDataForTable(&res, "sa-1", "ns-a", extractor.Identity{Name: "sa-1", Namespace: "ns-a", AutomountToken: true})
		saRBAC := extractor.ServiceAccountRBAC{
			Roles: []extractor.RBACRole{
				{Type: "Role", Name: "pod-reader", Namespace: "ns-a", Permissions: map[string]map[string]map[string]struct{}{
					"": {"pods": {"get": {}, "list": {}}},
				}},
			},
		}
		addRawRBACDataForTable(&res, "sa-1", "ns-a", saRBAC)
		addRawWorkloadDataForTable(&res, []extractor.Workload{
			{Type: "Deployment", Name: "app-deploy", Namespace: "ns-a", ServiceAccount: "sa-1", Containers: []extractor.Container{{Name: "main", Image: "nginx"}}},
		})

		metadataTable, identityTable, rbacTable, workloadTable, err := buildTables(res) // Pass only res
		if err != nil {
			t.Fatalf("buildTables returned error: %v", err)
		}
		if metadataTable == nil || identityTable == nil || rbacTable == nil || workloadTable == nil {
			t.Fatal("One or more tables are nil")
		}

		mdRendered := renderTableForTest(metadataTable)
		if !strings.Contains(mdRendered, "full-data-app") {
			t.Error("Metadata table missing app name")
		}
		if !strings.Contains(mdRendered, "v1.0") {
			t.Error("Metadata table missing version")
		}

		idRendered := renderTableForTest(identityTable)
		if !strings.Contains(idRendered, "sa-1") {
			t.Error("Identity table missing sa-1")
		}
		if !strings.Contains(idRendered, "ns-a") {
			t.Error("Identity table missing ns-a")
		}
		if identityTable.Length() != 1 {
			t.Errorf("Expected 1 identity, got %d", identityTable.Length())
		}

		rbacRendered := renderTableForTest(rbacTable)
		if !strings.Contains(rbacRendered, "sa-1") {
			t.Error("RBAC table missing sa-1")
		}
		if !strings.Contains(rbacRendered, "Role") {
			t.Error("RBAC table missing Role type")
		}
		if !strings.Contains(rbacRendered, "pod-reader") {
			t.Error("RBAC table missing pod-reader role")
		}
		if !strings.Contains(rbacRendered, "pods") {
			t.Error("RBAC table missing pods resource")
		}
		if !strings.Contains(rbacRendered, "get,list") && !strings.Contains(rbacRendered, "list,get") {
			t.Error("RBAC table missing get,list verbs")
		}
		if rbacTable.Length() != 1 {
			t.Errorf("Expected 1 RBAC entry (verbs combined), got %d", rbacTable.Length())
		}

		wlRendered := renderTableForTest(workloadTable)
		if !strings.Contains(wlRendered, "sa-1") {
			t.Error("Workload table missing sa-1")
		}
		if !strings.Contains(wlRendered, "Deployment") {
			t.Error("Workload table missing Deployment type")
		}
		if !strings.Contains(wlRendered, "app-deploy") {
			t.Error("Workload table missing app-deploy name")
		}
		if workloadTable.Length() != 1 {
			t.Errorf("Expected 1 workload, got %d", workloadTable.Length())
		}
	})

	t.Run("rbacDataWithRisk", func(t *testing.T) {
		res := newTableTestResult("risk-app", "v1", "risk-src", timestamp)
		saRBAC := extractor.ServiceAccountRBAC{
			Roles: []extractor.RBACRole{
				{Type: "ClusterRole", Name: "mega-admin", Namespace: "*", Permissions: map[string]map[string]map[string]struct{}{
					"*": {"*": {"*": {}}},
				}},
			},
		}
		addRawRBACDataForTable(&res, "risk-sa", "kube-system", saRBAC)

		_, _, rbacTable, _, err := buildTables(res) // Pass only res
		if err != nil {
			t.Fatalf("buildTables error: %v", err)
		}
		if rbacTable == nil {
			t.Fatal("rbacTable is nil")
		}

		rendered := renderTableForTest(rbacTable)
		if !strings.Contains(rendered, "Critical") {
			t.Errorf("Rendered RBAC table for high risk does not contain 'Critical':\n%s", rendered)
		}
		if !strings.Contains(rendered, "ClusterAdminAccess") {
			t.Errorf("Rendered RBAC table for high risk does not contain tag 'ClusterAdminAccess':\n%s", rendered)
		}
	})

	t.Run("invalidIdentityDataFormatInBuild", func(t *testing.T) {
		res := newTableTestResult("test", "v1", "src", timestamp)
		res.IdentityData.Data["identities"] = "not-a-map"
		_, _, _, _, err := buildTables(res)
		if err == nil {
			t.Fatal("buildTables should have failed for invalid identity format")
		}
		if !strings.Contains(err.Error(), "invalid Identity data format") {
			t.Errorf("Expected 'invalid Identity data format' in error, got: %v", err)
		}
	})

	t.Run("invalidRBACDataFormatInBuild", func(t *testing.T) {
		res := newTableTestResult("test", "v1", "src", timestamp)
		res.RBACData.Data["rbac"] = "not-a-map"
		_, _, _, _, err := buildTables(res)
		if err == nil {
			t.Fatal("buildTables should have failed for invalid RBAC format")
		}
		if !strings.Contains(err.Error(), "invalid RBAC data format") {
			t.Errorf("Expected 'invalid RBAC data format' in error, got: %v", err)
		}
	})

	t.Run("invalidWorkloadDataFormatInBuild", func(t *testing.T) {
		res := newTableTestResult("test", "v1", "src", timestamp)
		res.WorkloadData.Data["workloads"] = "not-a-map"
		_, _, _, _, err := buildTables(res)
		if err == nil {
			t.Fatal("buildTables should have failed for invalid workload format")
		}
		if !strings.Contains(err.Error(), "invalid Workload data format") {
			t.Errorf("Expected 'invalid Workload data format' in error, got: %v", err)
		}
	})
}

func renderTableForTest(tb table.Writer) string {
	// The table.Writer interface doesn't have a Render() method that returns a string directly
	// without reconfiguring output. This is a simplified way for testing.
	// In a real scenario, you'd set tb.SetOutputMirror(&buf) before tb.Render().
	// For these tests, we assume tb.Render() gives us the content if possible,
	// or this function might need to be adapted if tb.Render() writes to stdout.
	// For now, we'll use Render() and rely on string.Contains for checks.
	return tb.Render()
}

// NOTE: Further tests could include different options (e.g., no metadata for tables)
// and more complex data structures.
