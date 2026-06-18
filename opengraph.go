package golinhound

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"reflect"
	"slices"
	"strings"
)

type openGraph struct {
	Metadata struct {
		SourceKind string `json:"source_kind,omitempty"`
	} `json:"metadata"`
	Graph struct {
		Nodes []*openGraphNode `json:"nodes"`
		Edges []*openGraphEdge `json:"edges"`
	} `json:"graph"`
}

type openGraphNode struct {
	Kinds      []string               `json:"kinds"`
	ID         string                 `json:"id"`
	Properties map[string]interface{} `json:"properties"`
}

type openGraphNodeSelector struct {
	MatchBy string `json:"match_by"`
	Value   string `json:"value"`
	Kind    string `json:"kind,omitempty"`
}

type openGraphEdge struct {
	Kind       string                 `json:"kind"`
	Start      openGraphNodeSelector  `json:"start"`
	End        openGraphNodeSelector  `json:"end"`
	Properties map[string]interface{} `json:"properties"`
}

func newOpenGraphEdge(kind string, startId string, startKind string, endId string, endKind string, properties map[string]interface{}) *openGraphEdge {
	return &openGraphEdge{
		Kind: kind,
		Start: openGraphNodeSelector{
			MatchBy: "id",
			Value:   startId,
			Kind:    startKind,
		},
		End: openGraphNodeSelector{
			MatchBy: "id",
			Value:   endId,
			Kind:    endKind,
		},
		Properties: properties,
	}
}

// openGraphBaseGraph generates all OpenGraph nodes and edges that can be created from all LinhoundObjects
func openGraphBaseGraph(obj LinhoundObject) ([]*openGraphNode, []*openGraphEdge) {
	var nodes []*openGraphNode
	var edges []*openGraphEdge

	// define unique identifiers and displaynames
	computerId := obj.GetComputer().UniqueId
	computerName := obj.GetComputer().FQDN
	rootId := fmt.Sprintf("%s@%s", obj.GetComputer().RootName, computerId)
	rootName := fmt.Sprintf("%s@%s", obj.GetComputer().RootName, computerName)
	userId := fmt.Sprintf("%s@%s", obj.GetUserName(), computerId)
	userName := fmt.Sprintf("%s@%s", obj.GetUserName(), computerName)

	// create Computer
	nodes = append(nodes, &openGraphNode{
		Kinds: []string{"SSHComputer"},
		ID:    computerId,
		Properties: map[string]interface{}{
			"name": computerName,
			"FQDN": obj.GetComputer().FQDN,
		},
	})

	// create Root
	nodes = append(nodes, &openGraphNode{
		Kinds: []string{"SSHUser"},
		ID:    rootId,
		Properties: map[string]interface{}{
			"name": rootName,
		},
	})
	edges = append(edges, newOpenGraphEdge(
		"IsRoot",
		rootId, "SSHUser",
		computerId, "SSHComputer",
		map[string]interface{}{},
	))
	edges = append(edges, newOpenGraphEdge(
		"CanImpersonate",
		computerId, "SSHComputer",
		rootId, "SSHUser",
		map[string]interface{}{},
	))

	// create User
	nodes = append(nodes, &openGraphNode{
		Kinds: []string{"SSHUser"},
		ID:    userId,
		Properties: map[string]interface{}{
			"name": userName,
		},
	})
	edges = append(edges, newOpenGraphEdge(
		"CanImpersonate",
		computerId, "SSHComputer",
		userId, "SSHUser",
		map[string]interface{}{},
	))

	return nodes, edges
}

// openGraphKeypair transforms a LinhoundKey into an OpenGraph node
func openGraphKeypair(key LinhoundKey) *openGraphNode {
	pk := key.GetPublicKey()
	return &openGraphNode{
		Kinds: []string{"SSHKeyPair"},
		ID:    pk.FingerprintSHA256,
		Properties: map[string]interface{}{
			"name":              pk.FingerprintSHA256,
			"Base64":            pk.Base64,
			"Algorithm":         pk.Algorithm,
			"FingerprintSHA256": pk.FingerprintSHA256,
			"FingerprintMD5":    pk.FingerprintMD5,
			"FIDO2":             pk.FIDO2,
		},
	}
}

// LinhoundToOpenGraphObjects takes a Linhound object and transforms it into OpenGraph nodes and edges
func LinhoundToOpenGraphObjects(obj LinhoundObject) ([]*openGraphNode, []*openGraphEdge) {
	// Determine type of obj parameter
	objType := reflect.TypeOf(obj)
	if objType.Kind() == reflect.Ptr {
		objType = objType.Elem()
	}

	// variables to store results
	var nodes []*openGraphNode
	var edges []*openGraphEdge

	if slices.Contains([]string{"AuthorizedKey", "PrivateKey", "ForwardedKey", "Sudoer"}, objType.Name()) {
		// create (c:Computer)
		// create (root:User)
		// create (root)-[:IsRoot]->(c)
		// create (c)-[:CanImpersonate]->(r)
		// create (u:User)
		// create (c)-[:CanImpersonate]->(u)
		nodesTmp, edgesTmp := openGraphBaseGraph(obj)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}

	if slices.Contains([]string{"AuthorizedKey", "PrivateKey", "ForwardedKey"}, objType.Name()) {
		// create (k:KeyPair)
		node := openGraphKeypair(obj.(LinhoundKey))
		nodes = append(nodes, node)
	}

	if objType.Name() == "AuthorizedKey" {
		// create (k)->(u)
		ak := obj.(AuthorizedKey)
		edges = append(edges, newOpenGraphEdge(
			"CanSSH",
			ak.PublicKey.FingerprintSHA256, "SSHKeyPair",
			fmt.Sprintf("%s@%s", ak.UserName, ak.Computer.UniqueId), "SSHUser",
			map[string]interface{}{
				"FilePath": ak.FilePath,
				"Comment":  ak.PublicKey.Comment,
			},
		))
	}

	if objType.Name() == "PrivateKey" {
		// create (u)->(k)
		pk := obj.(PrivateKey)
		edges = append(edges, newOpenGraphEdge(
			"HasPrivateKey",
			fmt.Sprintf("%s@%s", pk.UserName, pk.Computer.UniqueId), "SSHUser",
			pk.PublicKey.FingerprintSHA256, "SSHKeyPair",
			map[string]interface{}{
				"FilePath":  pk.FilePath,
				"KeyFormat": pk.KeyFormat,
				"KDF":       pk.KDF,
				"Cipher":    pk.Cipher,
				"Encrypted": pk.Encrypted,
				"Comment":   pk.PublicKey.Comment,
			},
		))
	}

	if objType.Name() == "ForwardedKey" {
		// create (u)->(k)
		fk := obj.(ForwardedKey)
		edges = append(edges, newOpenGraphEdge(
			"ForwardsKey",
			fmt.Sprintf("%s@%s", fk.UserName, fk.Computer.UniqueId), "SSHUser",
			fk.PublicKey.FingerprintSHA256, "SSHKeyPair",
			map[string]interface{}{
				"LastLoginSocket": fk.LastLoginSocket,
				"LastLoginTime":   fk.LastLoginTime,
				"LastLoginIP":     fk.LastLoginIP,
				"Comment":         fk.PublicKey.Comment,
			},
		))
	}

	if objType.Name() == "Sudoer" {
		// create (u)->(c)
		s := obj.(Sudoer)
		edges = append(edges, newOpenGraphEdge(
			"CanSudo",
			fmt.Sprintf("%s@%s", s.UserName, s.Computer.UniqueId), "SSHUser",
			s.Computer.UniqueId, "SSHComputer",
			map[string]interface{}{
				"PasswordRequired": s.PasswordRequired,
				"Commands":         s.Commands,
			},
		))
	}

	return nodes, edges
}

// TODO
// (SSHComputer)<-[sameMachine]->(Computer)
func KeyTabToOpenGraph(obj Keytab) []*openGraphEdge {
	props := make(map[string]interface{})

	// convert principal and realm into Bloodhound name
	name, err := PrincipalToBloodhoundName(obj.ClientPrincipal, obj.ClientRealm)
	if err != nil {
		logVerbose("%v\n", err)
		return []*openGraphEdge{}
	}

	// create the edge
	props["FilePath"] = obj.FilePath
	edge := openGraphEdge{
		Kind: "HasKeytab",
		Start: openGraphNodeSelector{
			MatchBy: "id",
			Value:   obj.Computer.UniqueId,
			Kind:    "SSHComputer",
		},
		End: openGraphNodeSelector{
			MatchBy: "name",
			Value:   name,
		},
		Properties: props,
	}

	// For hostnames we need to specify the type of the end node
	// otherwise we create HasKeytab connections from SSHComputer to itself
	// because SSHComputer might have the same name as AD Computer
	if !strings.Contains(name, "@") {
		edge.End.Kind = "Computer"
	} else {
		edge.End.Kind = "User"
	}

	return []*openGraphEdge{&edge}
}

// TODO
func TGTToOpenGraph(obj TGT) []*openGraphEdge {
	props := make(map[string]interface{})

	// convert principal and realm into Bloodhound name
	name, err := PrincipalToBloodhoundName(obj.ClientPrincipal, obj.ClientRealm)
	if err != nil {
		logVerbose("%v\n", err)
		return []*openGraphEdge{}
	}

	props["FilePath"] = obj.FilePath
	props["StartTime"] = obj.StartTime
	props["EndTime"] = obj.EndTime
	props["RenewTime"] = obj.RenewTime

	edge := openGraphEdge{
		Kind: "HasTGT",
		Start: openGraphNodeSelector{
			MatchBy: "id",
			Value:   obj.Computer.UniqueId,
			Kind:    "SSHComputer",
		},
		End: openGraphNodeSelector{
			MatchBy: "name",
			Value:   name,
		},
		Properties: props,
	}

	// For hostnames we need to specify the type of the end node
	// otherwise we create HasTGT connections from SSHComputer to itself
	// because SSHComputer might have the same name as AD Computer
	if !strings.Contains(name, "@") {
		edge.End.Kind = "Computer"
	} else {
		edge.End.Kind = "User"
	}

	return []*openGraphEdge{&edge}
}

func AZVMToOpenGraph(obj AZVM) ([]*openGraphNode, []*openGraphEdge) {
	var nodes []*openGraphNode
	var edges []*openGraphEdge

	// create AZVM node
	nodes = append(nodes, &openGraphNode{
		Kinds: []string{"AZVM", "AZBase"},
		ID:    strings.ToUpper(obj.ResourceId),
		Properties: map[string]interface{}{
			"name":            strings.ToUpper(obj.Name),
			"tenantid":        strings.ToUpper(obj.TenantId),
			"operatingsystem": strings.ToUpper(obj.OperatingSystem),
		},
	})

	//(SSHComputer)-[sameMachine]->(AZVM)
	edges = append(edges, newOpenGraphEdge(
		"SameMachine",
		obj.Computer.UniqueId, "SSHComputer",
		strings.ToUpper(obj.ResourceId), "AZVM",
		map[string]interface{}{},
	))

	//(SSHComputer)<-[sameMachine]-(AZVM)
	edges = append(edges, newOpenGraphEdge(
		"SameMachine",
		strings.ToUpper(obj.ResourceId), "AZVM",
		obj.Computer.UniqueId, "SSHComputer",
		map[string]interface{}{},
	))
	// create
	return nodes, edges
}

// MergeOpenGraphJSONs reads OpenGraph JSON objects from stdin and merges them
func MergeOpenGraphJSONs() string {
	var merged openGraph

	// parse OpenGraph objects one by one and append them to result graph
	for decoder := json.NewDecoder(os.Stdin); ; {
		var tmp openGraph
		err := decoder.Decode(&tmp)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("[ERROR] Decoding JSON failed: %v\n", err)
		}
		merged.Graph.Nodes = append(merged.Graph.Nodes, tmp.Graph.Nodes...)
		merged.Graph.Edges = append(merged.Graph.Edges, tmp.Graph.Edges...)
	}

	// don't set source_kind because it leads to ingest problems
	// merged.Metadata.SourceKind = "GolinHound"
	// ensure uniqueness of nodes and edges
	merged.Graph.Nodes = unique(merged.Graph.Nodes)
	merged.Graph.Edges = unique(merged.Graph.Edges)

	// convert to json string
	jsonBytes, _ := json.Marshal(merged)
	return string(jsonBytes)
}

func PrincipalToBloodhoundName(principal string, realm string) (string, error) {
	principal = strings.ToUpper(principal)
	realm = strings.ToUpper(realm)

	// principal might not contain realm
	if !strings.Contains(principal, "@") {
		principal += "@" + realm
	}

	// UPN found
	// user@demo.local
	if !strings.Contains(principal, "/") && !strings.Contains(principal, "$@") {
		return principal, nil
	}

	// Machine Account UPN found
	// machine$@demo.local
	if !strings.Contains(principal, "/") && strings.Contains(principal, "$@") {
		principal = strings.ReplaceAll(principal, "$@", ".")
		return principal, nil
	}

	// Machine Account SPN found
	// host/machine@demo.local
	// host/machine.demo.local@demo.local
	if principal, found := strings.CutPrefix(principal, "HOST/"); found {
		// We verified that barely any Computers exist, that do not have their name after a HOST/ SPN
		// MATCH (c:Computer) WHERE size(c.serviceprincipalnames) > 0 AND ALL(spn IN c.serviceprincipalnames WHERE NOT toUpper(spn) CONTAINS "HOST/"+toUpper(c.name)) RETURN c
		// remove realm from principal string, as we want to create a Computer name (FQDN)
		principal = strings.ReplaceAll(principal, "@"+realm, "")
		// if the principal is a hostname instead of an FQDN, add the realm as domain
		if !strings.Contains(principal, ".") {
			principal = fmt.Sprintf("%s.%s", principal, realm)
		}
		return principal, nil
	}
	return "", fmt.Errorf("skipping principal: %s@%s", principal, realm)
}
