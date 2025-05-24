# RBAC Policy Ingestion

RBAC-Ops supports ingesting RBAC policies from various sources. This document describes the supported sources and their configuration options.

## Supported Sources

### 1. Local YAML Files

Single YAML files containing RBAC policies can be loaded directly:

```bash
rbac-ops analyze /path/to/policy.yaml
```

Supported extensions: `.yaml`, `.yml`

### 2. Remote YAML Files (HTTP/HTTPS)

RBAC policies can be loaded from remote HTTP/HTTPS URLs:

```bash
rbac-ops analyze https://example.com/policy.yaml
```

Requirements:

- URL must end with `.yaml` or `.yml`
- Server must respond with valid YAML content
- Content must contain valid RBAC policies

### 3. Directory of YAML Files

Recursively scan a directory for YAML files:

```bash
rbac-ops analyze /path/to/policies/
```

Features:

- Recursive directory traversal
- Optional symlink following
- Concurrent file processing
- Automatic YAML validation

## Configuration Options

The following options can be configured when ingesting RBAC policies:

| Option | Description | Default |
|--------|-------------|---------|
| `validate-yaml` | Validate YAML syntax before processing | `true` |
| `follow-symlinks` | Follow symbolic links when scanning directories | `false` |
| `max-concurrency` | Maximum number of concurrent file operations | `4` |

## Examples

1. Analyze a single policy file:

```bash
rbac-ops analyze ./examples/cluster-role.yaml
```

1. Analyze policies from a remote repository:

```bash
rbac-ops analyze https://raw.githubusercontent.com/org/repo/main/rbac.yaml
```

1. Analyze all policies in a directory with symlink following:

```bash
rbac-ops analyze ./policies/ --follow-symlinks
```

## Error Handling

The ingestion process includes robust error handling:

1. File errors:

   - Non-existent files/directories
   - Permission issues
   - Invalid symlinks

1. YAML errors:

   - Invalid YAML syntax
   - Missing required fields
   - Invalid RBAC policy structure

1. Network errors:

   - Invalid URLs
   - Connection timeouts
   - Non-200 HTTP responses
