package resolver

import "time"

// SourceType represents the type of source being resolved
type SourceType int

const (
	// SourceTypeUnknown represents an unknown source type
	SourceTypeUnknown SourceType = iota
	// SourceTypeFile represents a single YAML file
	SourceTypeFile
	// SourceTypeRemote represents a remote HTTP/HTTPS resource
	SourceTypeRemote
	// SourceTypeFolder represents a directory containing YAML files
	SourceTypeFolder
)

// ResolverMetadata contains information about the resolved source
type ResolverMetadata struct {
	// Name of the artifact
	Name string
	// Version of the artifact
	Version string
	// Type is the source type (file, folder, remote)
	Type SourceType
	// RendererType indicates the type of renderer used (yaml, helm, kustomize)
	RendererType RendererType
	// Path is the path to the source
	Path string
	// Size is the size of the source in bytes
	Size int64
	// ModTime is the last modification time of the source
	ModTime time.Time
	// Extra contains additional metadata specific to the source type
	Extra map[string]interface{}
}
