package collect

import (
	"context"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// Collector is implemented by each domain-scoped collector (Azure,
// AD, SSH, ...). ctx carries top-level cancellation.
type Collector interface {
	Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error
}

// Options is the tunable input to Run.
type Options struct {
	// WaitForKeysDuration bounds how long the SSH server collector
	// watches /tmp/ for new agent sockets, in minutes. Zero means
	// "do a one-shot glob and return".
	WaitForKeysDuration int
}
