package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigPrecedence(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  host: "127.0.0.1"
  port: 9090
  timeout: "1m"
  log_level: "debug"

`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Set environment variables (should override config file)
	os.Setenv("RBAC_OPS_SERVER_PORT", "9091")
	os.Setenv("RBAC_OPS_RBAC_DEFAULT_NAMESPACE", "env-ns")
	defer os.Unsetenv("RBAC_OPS_SERVER_PORT")
	defer os.Unsetenv("RBAC_OPS_RBAC_DEFAULT_NAMESPACE")

	// Load the configuration
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	// Test config file values
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Server.Host)
	}

	// Test environment variable override
	if cfg.Server.Port != 9091 {
		t.Errorf("expected port 9091, got %d", cfg.Server.Port)
	}

	// Test duration parsing
	expectedTimeout := time.Minute
	if cfg.Server.Timeout != expectedTimeout {
		t.Errorf("expected timeout %v, got %v", expectedTimeout, cfg.Server.Timeout)
	}
}

func TestDefaultValues(t *testing.T) {
	// Load config without any file or env vars
	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}

	// Test default values
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected default log level info, got %s", cfg.Server.LogLevel)
	}

}
