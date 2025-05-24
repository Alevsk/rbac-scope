package ingestor

import (
	"net/http"
	"testing"
)

func TestSourceTypeString(t *testing.T) {
	tests := []struct {
		name string
		st   SourceType
		want string
	}{
		{
			name: "file source type",
			st:   SourceTypeFile,
			want: "file",
		},
		{
			name: "remote source type",
			st:   SourceTypeRemote,
			want: "remote",
		},
		{
			name: "folder source type",
			st:   SourceTypeFolder,
			want: "folder",
		},
		{
			name: "unknown source type",
			st:   SourceTypeUnknown,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.st.String(); got != tt.want {
				t.Errorf("SourceType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolverFactory(t *testing.T) {
	h := newTestHelper(t)

	// Create test files
	clusterRole := h.readFixture("cluster-role.yaml")
	roleWithSecrets := h.readFixture("role-with-secrets.yaml")
	tmpDir := h.createTempDir(map[string]string{
		"test.yaml":        clusterRole,
		"invalid.yaml":     h.readFixture("invalid.yaml"),
		"subdir/role.yaml": roleWithSecrets,
	})
	defer h.cleanupTemp(tmpDir)

	// Setup mock HTTP client
	mockClient := newMockHTTPClient()
	mockClient.addResponse("http://example.com/rbac.yaml", http.StatusOK, clusterRole)
	mockClient.addResponse("https://example.com/rbac.yaml", http.StatusOK, roleWithSecrets)
	mockClient.addResponse("http://example.com/file.txt", http.StatusOK, "not a yaml file")

	// Override default HTTP client
	defaultHTTPClient = mockClient.GetClient()

	tests := []struct {
		name     string
		source   string
		wantErr  bool
		wantType SourceType
	}{
		{
			name:    "empty source",
			source:  "",
			wantErr: true,
		},
		{
			name:     "http url source",
			source:   "http://example.com/rbac.yaml",
			wantErr:  false,
			wantType: SourceTypeRemote,
		},
		{
			name:     "https url source",
			source:   "https://example.com/rbac.yaml",
			wantErr:  false,
			wantType: SourceTypeRemote,
		},
		{
			name:    "http url non-yaml",
			source:  "http://example.com/file.txt",
			wantErr: true,
		},
		{
			name:    "local file source",
			source:  "rbac.yaml",
			wantErr: true, // true for now until LocalYAMLResolver is implemented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ResolverFactory(tt.source, &Options{ValidateYAML: true})
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolverFactory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if !r.CanResolve(tt.source) {
				t.Error("Resolver cannot resolve the source")
			}

			// Test resolver output if we expect it to work
			if !tt.wantErr {
				h.verifyResolverOutput(r, false, tt.wantType)
			}
		})
	}
}
