package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
)

// AzureIMDSTimeout bounds each HTTP request to the Azure Instance
// Metadata Service.
const AzureIMDSTimeout = 3 * time.Second

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
	compute, err := azureIMDSInstanceCompute()
	if err != nil {
		return errors.New("Azure IMDS unreachable")
	}
	identity, err := azureIMDSIdentityInfo()
	if err != nil {
		return errors.New("Azure IMDS identity unavailable")
	}

	azID := strings.ToUpper(compute.ResourceId)
	b.AddNode([]string{"AZVM", "AZBase"}, azID, map[string]any{
		"name":            strings.ToUpper(compute.Name),
		"tenantid":        strings.ToUpper(identity.TenantId),
		"operatingsystem": strings.ToUpper(compute.OSType),
	})

	b.AddEdge("SameMachine",
		opengraph.ByID("SSHComputer", h.ComputerID()),
		opengraph.ByID("AZVM", azID),
		nil)
	b.AddEdge("SameMachine",
		opengraph.ByID("AZVM", azID),
		opengraph.ByID("SSHComputer", h.ComputerID()),
		nil)

	return nil
}

// azureIMDSInstanceCompute fetches /metadata/instance/compute from IMDS
// and returns the parsed metadataInstanceCompute (resource id, name,
// OS type). Returns the transport error verbatim when the request
// fails; returns a JSON-decode error when IMDS replies with something
// unparseable.
func azureIMDSInstanceCompute() (*metadataInstanceCompute, error) {
	body, err := azureIMDS("instance/compute")
	if err != nil {
		return nil, err
	}
	var md metadataInstanceCompute
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, err
	}
	return &md, nil
}

// azureIMDSIdentityInfo fetches /metadata/identity/info from IMDS and
// returns the parsed metadataIdentityInfo (tenant id only). Returns
// the transport error verbatim when the request fails; returns a
// JSON-decode error when IMDS replies with something unparseable.
func azureIMDSIdentityInfo() (*metadataIdentityInfo, error) {
	body, err := azureIMDS("identity/info")
	if err != nil {
		return nil, err
	}
	var md metadataIdentityInfo
	if err := json.Unmarshal(body, &md); err != nil {
		return nil, err
	}
	return &md, nil
}

// azureIMDS issues an HTTP GET with the metadata Header and returns the body.
func azureIMDS(path string) ([]byte, error) {
	client := &http.Client{Timeout: AzureIMDSTimeout}

	url := fmt.Sprintf("http://169.254.169.254/metadata/%s?api-version=2025-04-07", path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
