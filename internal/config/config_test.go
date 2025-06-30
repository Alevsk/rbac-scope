package config

import (
	"os"
	"path/filepath"
	"strings"
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
database:
  host: "localhost"
  port: 5432
  name: "rbac_scope"
  user: "postgres"
  password: "secret"
  ssl_mode: "disable"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Set environment variables (should override config file)
	os.Setenv("RBAC_SCOPE_SERVER_PORT", "9091")
	os.Setenv("RBAC_SCOPE_DATABASE_PASSWORD", "env-password")
	defer os.Unsetenv("RBAC_SCOPE_SERVER_PORT")
	defer os.Unsetenv("RBAC_SCOPE_DATABASE_PASSWORD")

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

	// Test database config
	if cfg.Database.Password != "env-password" {
		t.Errorf("expected database password env-password, got %s", cfg.Database.Password)
	}
	if cfg.Database.SSLMode != "disable" {
		t.Errorf("expected database ssl_mode disable, got %s", cfg.Database.SSLMode)
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
		t.Errorf("expected port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("expected log level info, got %s", cfg.Server.LogLevel)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("expected database host localhost, got %s", cfg.Database.Host)
	}
}

func TestConfigFileValidation(t *testing.T) {
	// Test non-existent config file
	_, err := Load("nonexistent.yml")
	if err == nil {
		t.Error("expected error for non-existent config file")
	}

	// Test invalid config file path
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid/config.yml")
	_, err = Load(configPath)
	if err == nil {
		t.Error("expected error for invalid config file path")
	}
}

func TestInvalidValues(t *testing.T) {
	// Create config with invalid values
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  port: "invalid"
  timeout: "invalid"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	// Test invalid port
	os.Setenv("RBAC_SCOPE_SERVER_PORT", "invalid")
	defer os.Unsetenv("RBAC_SCOPE_SERVER_PORT")

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid port")
	}
}

func TestInvalidDuration(t *testing.T) {
	// Create config with invalid duration
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := []byte(`
server:
  timeout: "invalid"
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestLoadConfigWithEnvVarPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "env_config.yml")
	configContent := []byte(`debug: true
server:
  port: 1234`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	originalEnvVal := os.Getenv(RbacOpsConfigPathEnvVar)
	os.Setenv(RbacOpsConfigPathEnvVar, configPath)
	t.Cleanup(func() {
		os.Setenv(RbacOpsConfigPathEnvVar, originalEnvVal)
	})

	cfg, err := Load("") // Pass empty string to trigger env var check
	if err != nil {
		t.Fatalf("Load() error = %v, wantErr nil", err)
	}
	if !cfg.Debug {
		t.Errorf("cfg.Debug = %v, want true", cfg.Debug)
	}
	if cfg.Server.Port != 1234 {
		t.Errorf("cfg.Server.Port = %d, want 1234", cfg.Server.Port)
	}
}

func TestLoadConfigWithEnvVarPathNonExistent(t *testing.T) {
	nonExistentPath := filepath.Join(t.TempDir(), "non_existent_config.yml") // Use TempDir for safety
	originalEnvVal := os.Getenv(RbacOpsConfigPathEnvVar)
	os.Setenv(RbacOpsConfigPathEnvVar, nonExistentPath)
	t.Cleanup(func() {
		os.Setenv(RbacOpsConfigPathEnvVar, originalEnvVal)
	})

	_, err := Load("") // Pass empty string to trigger env var check
	if err == nil {
		t.Fatalf("Load() error = nil, wantErr non-nil")
	}
	expectedErrorMsg := "config file specified in " + RbacOpsConfigPathEnvVar + " not found: " + nonExistentPath
	if !strings.Contains(err.Error(), expectedErrorMsg) { // Use Contains for flexibility
		t.Errorf("Load() error = %q, want to contain %q", err.Error(), expectedErrorMsg)
	}
}

func TestLoadConfigWithAlternativeYamlName(t *testing.T) {
	tmpDir := t.TempDir()
	// Create config.yaml, but not config.yml
	configYamlPath := filepath.Join(tmpDir, "config.yaml")
	configContent := []byte(`debug: false
server:
  port: 5678`)
	if err := os.WriteFile(configYamlPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	originalWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(originalWd); err != nil {
			t.Fatal(err)
		}
	})

	// Ensure config.yml does not exist in tmpDir (it shouldn't by default)
	// No need to explicitly delete if TempDir is fresh

	cfg, err := Load("") // configPath is empty, should find config.yaml
	if err != nil {
		t.Fatalf("Load() error = %v, wantErr nil", err)
	}
	if cfg.Debug {
		t.Errorf("cfg.Debug = %v, want false", cfg.Debug)
	}
	if cfg.Server.Port != 5678 {
		t.Errorf("cfg.Server.Port = %d, want 5678", cfg.Server.Port)
	}
}

func TestLoadConfigMalformedYaml(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "malformed_config.yml")
	// Create a malformed YAML file (e.g., unclosed quote)
	configContent := []byte(`
server:
  host: "localhost
  port: 1234
`)
	if err := os.WriteFile(configPath, configContent, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatalf("Load() error = nil, wantErr non-nil for malformed YAML")
	}
	// Check if the error message contains a hint of YAML parsing error
	// Specific error messages from Viper can be complex, so we check for a general indication.
	if !strings.Contains(err.Error(), "While parsing config") && !strings.Contains(err.Error(), "yaml") {
		t.Errorf("Load() error = %q, expected error indicating YAML parsing issue", err.Error())
	}
}
