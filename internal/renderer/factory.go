package renderer

// RendererType represents the type of renderer
type RendererType string

const (
	// RendererTypeYAML represents a YAML/JSON renderer
	RendererTypeYAML RendererType = "yaml"
)

// RendererFactory creates renderers based on type
type RendererFactory struct {
	defaultOpts *Options
}

// NewRendererFactory creates a new RendererFactory with default options
func NewRendererFactory(opts *Options) *RendererFactory {
	if opts == nil {
		opts = DefaultOptions()
	}
	return &RendererFactory{defaultOpts: opts}
}

// GetRenderer returns a renderer based on the given type
func (f *RendererFactory) GetRenderer(typ RendererType) (Renderer, error) {
	switch typ {
	case RendererTypeYAML:
		r := NewYAMLRenderer()
		if err := r.SetOptions(f.defaultOpts); err != nil {
			return nil, err
		}
		return r, nil
	default:
		return nil, ErrInvalidFormat
	}
}
