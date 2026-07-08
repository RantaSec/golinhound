package collect

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// Run builds Host, iterates every Windows domain collector, then
// finishes with OSCollector so its referenced-users pass sees every
// ReferenceUser mark. Currently runs only the Azure and SSH client
// collectors plus the Windows-side OSCollector (SSHComputer, local
// Administrators). AD and the SSH server collector are Linux-specific.
func Run(ctx context.Context, _ Options) (string, error) {
	slog.Info("Windows collection is limited to local user accounts, private keys, and Azure metadata")

	h, err := NewHost()
	if err != nil {
		return "", err
	}
	b := opengraph.NewGraphBuilder()

	collectors := []Collector{
		&AzureCollector{},
		&SSHClientCollector{},
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
