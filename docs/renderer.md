# Renderers

The `rbac-ops` tool supports multiple renderers to process different types of Kubernetes manifest sources. Each renderer is specialized in handling specific formats and converting them into a unified set of YAML manifests.

## Available Renderers

### YAML Renderer

The `YAMLRenderer` is the default renderer for processing raw YAML files. It handles:

- Single YAML documents
- Multi-document YAML files
- Basic YAML validation
- JSON files (automatically converted to YAML)

Used by:

- `LocalYAMLResolver` for local YAML files
- `RemoteYAMLResolver` for remote YAML resources

### Helm Renderer

The `HelmRenderer` processes Helm charts and templates. It supports:

- Chart.yaml validation
- Template rendering with values
- Dependency resolution
- Multi-document output

Used by:

- `FolderResolver` when a directory contains a `Chart.yaml` file

### Kustomize Renderer

The `KustomizeRenderer` handles Kustomize-based configurations. Features include:

- kustomization.yaml processing
- Resource composition
- Patches and transformers
- Cross-cutting field modifications
- Namespace management

Used by:

- `FolderResolver` when a directory contains a `kustomization.yaml` file

## Renderer Selection

The appropriate renderer is automatically selected based on the source type:

1. For directories:
   - If `Chart.yaml` is present → HelmRenderer
   - If `kustomization.yaml` is present → KustomizeRenderer
   - Otherwise → YAMLRenderer

2. For single files:
   - YAMLRenderer is used

3. For remote resources:
   - YAMLRenderer is used

## Output Format

All renderers produce a consistent output format:

```go
type Result struct {
    Manifests []Manifest // List of rendered Kubernetes manifests
}

type Manifest struct {
    Name     string // Name of the manifest
    Content  []byte // Raw YAML content
    Metadata map[string]interface{} // Additional metadata
}
```

## Configuration

Renderers can be configured using the `Options` struct:

```go
type Options struct {
    // Common options for all renderers
    ValidateInput bool // Whether to validate input before rendering
    StrictParsing bool // Whether to use strict YAML parsing

    // Helm-specific options
    Values map[string]interface{} // Values to use for Helm template rendering

    // Kustomize-specific options
    LoadRestrictions string // LoadRestrictions for Kustomize
}
```
