package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

const (
	// AzureIMDSTimeout bounds each HTTP request to the Azure Instance
	// Metadata Service.
	AzureIMDSTimeout = 3 * time.Second
	// MaxIMDSResponseSize caps Azure IMDS JSON response reads.
	MaxIMDSResponseSize = 4 << 20 // 4 MiB
)

var imdsHTTPClient = &http.Client{
	Transport: &http.Transport{Proxy: nil},
}

type metadataInstanceCompute struct {
	ResourceId string `json:"resourceId"`
	Name       string `json:"name"`
	OSType     string `json:"osType"`
}

type metadataIdentityInfo struct {
	TenantId string `json:"tenantId"`
}

// AzureCollector queries the Azure Instance Metadata Service (IMDS) at
// the link-local address 169.254.169.254 and emits AZVM/AZBase nodes
// plus bidirectional SameMachine edges joining the local SSHComputer
// to its Azure twin. Returns an error from Collect when IMDS is
// unreachable, which is the expected case on non-Azure hosts; the
// driver logs all such early returns uniformly.
type AzureCollector struct{}

// Collect fetches instance and identity metadata from IMDS and adds an
// AZVM/AZBase node plus two SameMachine edges (host <-> Azure twin) to b.
func (c *AzureCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	compute, err := azureIMDS[metadataInstanceCompute](ctx, "instance/compute")
	if err != nil {
		return fmt.Errorf("Azure IMDS unreachable: %w", err)
	}
	if compute.ResourceId == "" {
		return errors.New("Azure IMDS returned empty resourceId")
	}
	identity, err := azureIMDS[metadataIdentityInfo](ctx, "identity/info")
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("Azure IMDS identity unavailable: %w", err)
		}
		slog.Debug("Azure IMDS identity unavailable; proceeding with empty tenantId", "err", err)
	}

	azID := strings.ToUpper(compute.ResourceId)
	b.AddNode([]string{"AZVM", "AZBase"}, azID, map[string]any{
		"name":            strings.ToUpper(compute.Name),
		"tenantid":        strings.ToUpper(identity.TenantId),
		"operatingsystem": strings.ToUpper(compute.OSType),
	})

	b.AddEdge("GLH_SameMachine",
		opengraph.ByID("GLH_SSHComputer", h.ComputerID()),
		opengraph.ByID("AZVM", azID),
		nil)
	b.AddEdge("GLH_SameMachine",
		opengraph.ByID("AZVM", azID),
		opengraph.ByID("GLH_SSHComputer", h.ComputerID()),
		nil)

	return nil
}

// azureIMDS fetches /metadata/<path> from the Azure Instance Metadata
// Service and decodes the JSON response into T. Each call respects ctx
// cancellation, is bounded by AzureIMDSTimeout, bypasses environment
// HTTP proxies, and caps the response read at MaxIMDSResponseSize;
// non-200 responses, transport failures, and invalid JSON return an error.
func azureIMDS[T any](ctx context.Context, path string) (T, error) {
	var out T
	if err := ctx.Err(); err != nil {
		return out, err
	}
	cctx, cancel := context.WithTimeout(ctx, AzureIMDSTimeout)
	defer cancel()

	url := fmt.Sprintf("http://169.254.169.254/metadata/%s?api-version=2025-04-07", path)
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("Metadata", "true")

	resp, err := imdsHTTPClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("IMDS HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxIMDSResponseSize)).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}
