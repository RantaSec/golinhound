package opengraph

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// openGraph is the top-level wire envelope BloodHound's OpenGraph
// importer ingests: a metadata block plus a graph block holding the
// node and edge arrays.
type openGraph struct {
	Metadata struct {
		SourceKind string `json:"source_kind,omitempty"`
	} `json:"metadata"`
	Graph struct {
		Nodes []*openGraphNode `json:"nodes"`
		Edges []*openGraphEdge `json:"edges"`
	} `json:"graph"`
}

// openGraphNode is the wire shape of one node in the envelope. Kinds
// is the BloodHound kind list (e.g. ["SSHUser"] or ["AZVM","AZBase"]);
// ID is the unique identifier within the source; Properties is the
// free-form bag emitted by collectors.
type openGraphNode struct {
	Kinds      []string       `json:"kinds"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

// openGraphEdge is the wire shape of one edge. Kind is the relationship
// label (e.g. "CanSSH", "HasPrivateKey"); Start and End are
// node-selector references; Properties is the per-edge payload.
type openGraphEdge struct {
	Kind       string                `json:"kind"`
	Start      openGraphNodeSelector `json:"start"`
	End        openGraphNodeSelector `json:"end"`
	Properties map[string]any        `json:"properties,omitempty"`
}

// openGraphNodeSelector is the wire shape of one endpoint of an edge.
// MatchBy picks the resolution strategy ("id" or "property"); Value
// carries the id for "id", PropertyMatchers carries the AND-combined
// predicates for "property". Mixing Value and PropertyMatchers is a
// BloodHound validation error. ByID / ByProperty enforce the split.
// Always construct via ByID / ByProperty, never as a struct literal.
type openGraphNodeSelector struct {
	MatchBy          string            `json:"match_by"`
	Value            string            `json:"value,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	PropertyMatchers []propertyMatcher `json:"property_matchers,omitempty"`
}

// propertyMatcher is one entry of a `match_by: "property"` selector's
// property_matchers array. BloodHound currently only supports
// Operator="equals".
type propertyMatcher struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// ByID builds a node selector that resolves a BloodHound node by its
// unique id.
func ByID(kind, id string) openGraphNodeSelector {
	return openGraphNodeSelector{MatchBy: "id", Kind: kind, Value: id}
}

// ByProperty builds a node selector that resolves a BloodHound node by
// an AND-combination of (key, value) property matchers. Used when the
// endpoint is owned by a different collector and the only shared keys
// are properties. At least one matcher is required; slower than ByID
// at ingest time.
//
// Requires BloodHound CE v9.1.0 (commit 33d9287f) or later.
func ByProperty(kind string, matchers ...propertyMatcher) openGraphNodeSelector {
	return openGraphNodeSelector{MatchBy: "property", Kind: kind, PropertyMatchers: matchers}
}

// PropEq is shorthand for a property matcher with operator "equals" —
// currently the only operator BloodHound supports.
func PropEq(key string, value any) propertyMatcher {
	return propertyMatcher{Key: key, Operator: "equals", Value: value}
}

// GraphBuilder accumulates nodes and edges as collectors emit them.
type GraphBuilder struct {
	nodes []*openGraphNode
	edges []*openGraphEdge
}

// NewGraphBuilder returns an empty builder.
func NewGraphBuilder() *GraphBuilder { return &GraphBuilder{} }

// AddNode appends a node. Duplicate IDs are absorbed at Marshal time.
func (b *GraphBuilder) AddNode(kinds []string, id string, props map[string]any) {
	b.nodes = append(b.nodes, &openGraphNode{
		Kinds:      kinds,
		ID:         id,
		Properties: props,
	})
}

// AddEdge appends an edge between two node selectors. Both selectors
// must be constructed via ByID / ByProperty so MatchBy is set.
func (b *GraphBuilder) AddEdge(kind string, start, end openGraphNodeSelector, props map[string]any) {
	b.edges = append(b.edges, &openGraphEdge{
		Kind:       kind,
		Start:      start,
		End:        end,
		Properties: props,
	})
}

// Marshal dedups via unique[T] and serializes the OpenGraph envelope.
func (b *GraphBuilder) Marshal() string {
	var og openGraph
	og.Graph.Nodes = unique(b.nodes)
	og.Graph.Edges = unique(b.edges)
	bytes, _ := json.Marshal(og)
	return string(bytes)
}

// unique deduplicates a slice of pointers by JSON-marshal equality.
// Nodes/edges with identical content are folded
func unique[T any](elements []*T) []*T {
	seen := make(map[string]struct{})
	var result []*T
	for _, element := range elements {
		bytes, _ := json.Marshal(element)
		key := string(bytes)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, element)
		}
	}
	return result
}

// MergeOpenGraphJSONs reads a stream of OpenGraph JSON objects from r
// and emits a single merged envelope, deduplicating identical nodes and
// edges via unique[T]. Powers the `golinhound merge` subcommand.
func MergeOpenGraphJSONs(r io.Reader) ([]byte, error) {
	var merged openGraph
	dec := json.NewDecoder(r)
	for {
		var tmp openGraph
		if err := dec.Decode(&tmp); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decoding OpenGraph JSON: %w", err)
		}
		merged.Graph.Nodes = append(merged.Graph.Nodes, tmp.Graph.Nodes...)
		merged.Graph.Edges = append(merged.Graph.Edges, tmp.Graph.Edges...)
	}
	merged.Graph.Nodes = unique(merged.Graph.Nodes)
	merged.Graph.Edges = unique(merged.Graph.Edges)
	out, err := json.Marshal(merged)
	if err != nil {
		return nil, fmt.Errorf("marshaling merged OpenGraph: %w", err)
	}
	return out, nil
}
