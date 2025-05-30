# Formatter Package Documentation

The formatter package provides different output formats for displaying RBAC analysis results. Each format is optimized for different use cases and viewing contexts.

## Available Formats

### 1. JSON Format (`json`)
- Structured output in JSON format
- Ideal for programmatic consumption and API responses
- Pretty-printed with proper indentation
- Example structure:
```json
{
  "metadata": {
    "version": "1.0.0",
    "name": "example",
    "source": "path/to/source",
    "timestamp": 1234567890
  },
  "serviceAccountData": [...],
  "serviceAccountPermissions": [...],
  "serviceAccountWorkloads": [...]
}
```

### 2. YAML Format (`yaml`)
- Human-readable YAML output
- Good for configuration files and documentation
- Maintains the same structure as JSON but in YAML syntax
- Example structure:
```yaml
metadata:
  version: 1.0.0
  name: example
  source: path/to/source
  timestamp: 1234567890
serviceAccountData:
  - ...
serviceAccountPermissions:
  - ...
serviceAccountWorkloads:
  - ...
```

### 3. Table Format (`table`)
- Plain text table output using go-pretty/v6/table
- Optimized for terminal viewing
- Displays four main sections:
  1. METADATA: Basic information about the analysis
  2. SERVICE ACCOUNTS: Identity information for each service account
  3. RBAC PERMISSIONS: Role bindings and permissions
  4. SERVICE ACCOUNT WORKLOADS: Container and deployment information

### 4. Markdown Format (`markdown`)
- Markdown-formatted tables
- Ideal for documentation and GitHub/GitLab rendering
- Same four sections as the table format but with markdown syntax
- Can be directly embedded in markdown documents

## Data Structure

Each format displays the following information:

### Metadata
- Version: Version of the analysis
- Name: Name of the analyzed resource
- Source: Source of the RBAC data
- Timestamp: Time of analysis

### Service Account Data
- Service Account Name
- Namespace
- Automount Token Status
- Associated Secrets
- Image Pull Secrets

### RBAC Permissions
- Service Account Name
- Namespace
- Role Type (Role/ClusterRole)
- Role Name
- API Group
- Resource
- Verbs (Permissions)
- Risk Level

### Workload Data
- Service Account Name
- Namespace
- Workload Type
- Workload Name
- Container Name
- Container Image

## Usage

To specify the output format, use the `--output-format` flag with one of the following values:
- `json`
- `yaml`
- `table`
- `markdown`

Example:
```bash
rbac-ops analyze --output-format markdown ./manifests/
```

## Configuration

The formatter can be configured with the following options:

- `IncludeMetadata`: Whether to include metadata in the output (default: true)

These options can be set programmatically when creating a new formatter:

```go
opts := &formatter.Options{
    IncludeMetadata: true,
}
f, err := formatter.NewFormatter(formatter.TypeJSON, opts)
```
