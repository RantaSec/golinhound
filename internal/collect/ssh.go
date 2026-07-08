package collect

import (
	"strings"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"golang.org/x/crypto/ssh"
)

// publicKey is the internal carrier for what becomes one SSHKeyPair
// node. The fields are the complete property set on that node.
type publicKey struct {
	Comment           string
	Algorithm         string
	FingerprintSHA256 string
	FingerprintMD5    string
	FIDO2             bool
}

// newPublicKey derives the algorithm, canonical SHA256/MD5 fingerprints,
// and FIDO2 flag from an already-parsed ssh.PublicKey.
func newPublicKey(pub ssh.PublicKey, comment string) *publicKey {
	algo := pub.Type()
	return &publicKey{
		Comment:           comment,
		Algorithm:         algo,
		FingerprintSHA256: strings.TrimPrefix(ssh.FingerprintSHA256(pub), "SHA256:"),
		FingerprintMD5:    ssh.FingerprintLegacyMD5(pub),
		FIDO2:             strings.HasPrefix(algo, "sk-"),
	}
}

// emitKeypairNode adds an SSHKeyPair node.
func emitKeypairNode(b *opengraph.GraphBuilder, pk publicKey) {
	b.AddNode([]string{"SSHKeyPair"}, pk.FingerprintSHA256, map[string]any{
		"name":              pk.FingerprintSHA256,
		"Algorithm":         pk.Algorithm,
		"FingerprintSHA256": pk.FingerprintSHA256,
		"FingerprintMD5":    pk.FingerprintMD5,
		"FIDO2":             pk.FIDO2,
	})
}
