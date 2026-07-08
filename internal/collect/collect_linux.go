package collect

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// Run builds Host, iterates every Linux domain collector, then
// finishes with OSCollector so its referenced-users pass sees every
// ReferenceUser mark. Returns the marshaled OpenGraph JSON. The error
// return is non-nil ONLY when NewHost fails (startup preconditions:
// not root, missing /etc/machine-id or /etc/passwd, hostname lookup);
// once the Host is built, Run always returns (json, nil).
func Run(ctx context.Context, opts Options) (string, error) {
	h, err := NewHost()
	if err != nil {
		return "", err
	}
	b := opengraph.NewGraphBuilder()

	collectors := []Collector{
		&AzureCollector{},
		&ADCollector{},
		&SSHClientCollector{CollectExpiredCertificates: opts.CollectExpiredCertificates},
		&SSHServerCollector{WaitForKeysDuration: opts.WaitForKeysDuration},
	}
	for _, c := range collectors {
		if err := c.Collect(ctx, h, b); err != nil {
			slog.Info("collector skipped", "collector", fmt.Sprintf("%T", c), "reason", err)
		}
	}

	finalizer := &OSCollector{}
	if err := finalizer.Finalize(ctx, h, b); err != nil {
		slog.Info("collector skipped", "collector", fmt.Sprintf("%T", finalizer), "reason", err)
	}
	return b.Marshal(), nil
}
