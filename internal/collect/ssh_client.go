package collect

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"golang.org/x/crypto/ssh"
)

// SSHClientCollector emits private-key artifacts for every local user.
type SSHClientCollector struct{}

// Collect walks every user's ~/.ssh and emits SSHKeyPair nodes plus
// HasPrivateKey edges from the user to each parseable private key.
func (c *SSHClientCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	for _, u := range h.Users {
		emitPrivateKeys(h, u, b)
	}
	return nil
}

// emitPrivateKeys adds a KeyPair node and a HasPrivateKey edge for every
// private key.
func emitPrivateKeys(h *Host, u *User, b *opengraph.GraphBuilder) {
	slog.Debug("emitPrivateKeys", "userName", u.UserName)
	for _, privKeyFile := range privateKeysFiles(u.HomeDir) {
		pemBytes, err := os.ReadFile(privKeyFile)
		if err != nil {
			slog.Debug("emitPrivateKeys: could not open private key", "userName", u.UserName, "privKeyFile", privKeyFile)
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			slog.Debug("emitPrivateKeys: potential private key could not be decoded", "userName", u.UserName, "privKeyFile", privKeyFile)
			continue
		}

		var pk *privateKey
		switch {
		case block.Type == "OPENSSH PRIVATE KEY":
			pk, _ = parsePrivateKeyOpenSSH(u.UserName, privKeyFile, block.Bytes)
		case block.Type == "PRIVATE KEY":
			pk, _ = parsePrivateKeyUnencrypted(u.UserName, privKeyFile, pemBytes, "PKCS#8")
		case block.Type == "RSA PRIVATE KEY" && block.Headers["DEK-Info"] == "":
			pk, _ = parsePrivateKeyUnencrypted(u.UserName, privKeyFile, pemBytes, "PEM")
		case block.Type == "ENCRYPTED PRIVATE KEY", block.Type == "RSA PRIVATE KEY" && block.Headers["DEK-Info"] != "":
			// Both encrypted branches need the .pub file to recover the
			// public key (it isn't recoverable from the encrypted blob).
			pubKeyBytes, err := os.ReadFile(privKeyFile + ".pub")
			if err != nil {
				slog.Debug("emitPrivateKeys: public key could not be read", "userName", u.UserName, "pubKeyFile", privKeyFile+".pub")
				continue
			}
			pub, comment, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
			if err != nil {
				slog.Debug("emitPrivateKeys: ssh.ParseAuthorizedKey failed", "pubKeyFile", privKeyFile+".pub", "err", err)
				continue
			}
			pubKey := newPublicKey(pub, comment)
			if block.Type == "ENCRYPTED PRIVATE KEY" {
				pk, _ = parsePrivateKeyPKCS8Encrypted(u.UserName, privKeyFile, block.Bytes, *pubKey)
			} else {
				pk = parsePrivateKeyPEMEncrypted(u.UserName, privKeyFile, block.Headers["DEK-Info"], *pubKey)
			}
		default:
			continue
		}

		if pk == nil {
			continue
		}

		emitKeypairNode(b, pk.PublicKey)
		b.AddEdge("HasPrivateKey",
			opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
			opengraph.ByID("SSHKeyPair", pk.PublicKey.FingerprintSHA256),
			map[string]any{
				"FilePath":  pk.FilePath,
				"KeyFormat": pk.KeyFormat,
				"KDF":       pk.KDF,
				"Cipher":    pk.Cipher,
				"Encrypted": pk.Encrypted,
				"Comment":   pk.PublicKey.Comment,
			})
	}
}

// privateKeysFiles returns potential private-key files in ~/.ssh/.
// Excludes anything ending in .pub, plus the well-known non-key files.
func privateKeysFiles(userDir string) []string {
	slog.Debug("privateKeysFiles", "userDir", userDir)
	pattern := filepath.Join(userDir, ".ssh", "*")
	candidates, err := filepath.Glob(pattern)
	if err != nil {
		slog.Debug("privateKeysFiles: invalid glob pattern", "userDir", userDir)
	}
	var files []string
	for _, f := range candidates {
		base := filepath.Base(f)
		if strings.HasSuffix(base, ".pub") ||
			base == "config" ||
			base == "known_hosts" ||
			base == "authorized_keys" ||
			base == "authorized_keys2" {
			continue
		}
		files = append(files, f)
	}
	return files
}

// privateKey is the internal carrier for what becomes one HasPrivateKey
// edge. The fields are the complete property set on that edge plus its
// SSHKeyPair endpoint (PublicKey).
type privateKey struct {
	UserName  string
	PublicKey publicKey
	FilePath  string
	KeyFormat string
	KDF       string
	Cipher    string
	Encrypted bool
}

// newPrivateKey builds a privateKey with KDF and Cipher passed through
// normalizeAlgorithms (lowercased, dash-canonicalized, "" -> "none").
// Encrypted is set when the normalized cipher is not "none".
func newPrivateKey(userName string, pub publicKey, filePath, keyFormat, kdf, cipher string) *privateKey {
	kdf = normalizeAlgorithms(kdf)
	cipher = normalizeAlgorithms(cipher)
	return &privateKey{
		UserName:  userName,
		PublicKey: pub,
		FilePath:  filePath,
		KeyFormat: keyFormat,
		KDF:       kdf,
		Cipher:    cipher,
		Encrypted: cipher != "none",
	}
}

// normalizeAlgorithms canonicalizes KDF/cipher names across formats.
func normalizeAlgorithms(algorithm string) string {
	if algorithm == "" {
		return "none"
	}
	algorithm = strings.ToLower(algorithm)
	algorithm = strings.ReplaceAll(algorithm, "aes-", "aes")
	algorithm = strings.ReplaceAll(algorithm, "aes128_", "aes128-")
	algorithm = strings.ReplaceAll(algorithm, "aes256_", "aes256-")
	return algorithm
}

// parsePrivateKeyOpenSSH parses the OpenSSH proprietary "openssh-key-v1"
// private-key format: verifies the auth-magic prefix, unmarshals the
// CipherName/KdfName header, and recovers the public-key blob (which is
// in cleartext even for encrypted keys).
func parsePrivateKeyOpenSSH(userName, privKeyPath string, privKeyRaw []byte) (*privateKey, error) {
	slog.Debug("parsePrivateKeyOpenSSH", "userName", userName, "privKeyPath", privKeyPath)
	const privateKeyAuthMagic = "openssh-key-v1\x00"
	type openSSHEncryptedPrivateKey struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	if len(privKeyRaw) < len(privateKeyAuthMagic) || string(privKeyRaw[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, fmt.Errorf("[ERROR] '%s' not a valid OpenSSH private key", privKeyPath)
	}
	remaining := privKeyRaw[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, fmt.Errorf("[ERROR] OpenSSH private key unmarshal failed: '%s'", privKeyPath)
	}

	pub, err := ssh.ParsePublicKey(w.PubKey)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] OpenSSH private key public-key blob could not be parsed: '%s'", privKeyPath)
	}
	pubKey := newPublicKey(pub, "")

	return newPrivateKey(userName, *pubKey, privKeyPath, "openssh-key-v1", w.KdfName, w.CipherName), nil
}

// parsePrivateKeyUnencrypted parses an unencrypted PEM private key
// (both PKCS#8 "PRIVATE KEY" and traditional PEM "RSA PRIVATE KEY" with
// no DEK-Info) and derives the public key via crypto.PublicKey.
func parsePrivateKeyUnencrypted(userName, privKeyPath string, pemBytes []byte, keyFormat string) (*privateKey, error) {
	slog.Debug("parsePrivateKeyUnencrypted", "userName", userName, "privKeyPath", privKeyPath, "keyFormat", keyFormat)
	type withPublic interface {
		Public() crypto.PublicKey
	}
	cryptoPrivKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] unencrypted PKCS#8 key could not be parsed: '%s'", privKeyPath)
	}
	pub, err := ssh.NewPublicKey(cryptoPrivKey.(withPublic).Public())
	if err != nil {
		return nil, fmt.Errorf("[ERROR] corresponding PKCS#8 public key could not be calculated: '%s'", privKeyPath)
	}
	pubKey := newPublicKey(pub, "")

	return newPrivateKey(userName, *pubKey, privKeyPath, keyFormat, "", ""), nil
}

// parsePrivateKeyPKCS8Encrypted handles both PBES1 and PBES2 PKCS#8 envelopes.
// The OID dictates which.
//
// PBES1 keys (pbeWithXxxAnd<cipher>-CBC, OIDs 1.2.840.113549.1.5.{1,3,4,6,10,11})
// have a fixed KDF (PBKDF1) embedded in the algorithm name itself. PBES2
// keys (OID 1.2.840.113549.1.5.13) carry separate KDF + EncryptionScheme
// parameters that we resolve via the OID table.
func parsePrivateKeyPKCS8Encrypted(userName, privKeyPath string, privKeyBytes []byte, pub publicKey) (*privateKey, error) {
	slog.Debug("parsePrivateKeyPKCS8Encrypted", "userName", userName, "privKeyPath", privKeyPath)
	// RFC 5208 §A
	type encryptedPrivateKeyInfo struct {
		EncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedData       []byte
	}
	// RFC 8018 §A.4
	type pbes2Params struct {
		KeyDerivationFunc pkix.AlgorithmIdentifier
		EncryptionScheme  pkix.AlgorithmIdentifier
	}

	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(privKeyBytes, &epki); err != nil {
		return nil, fmt.Errorf("[ERROR] EncryptedPrivateKeyInfo of PKCS#8 private key could not be parsed: '%s'", privKeyPath)
	}

	encAlgOid := epki.EncryptionAlgorithm.Algorithm.String()
	encAlg, ok := pkcs8OIDToAlgorithm[encAlgOid]
	if !ok {
		return nil, fmt.Errorf("[ERROR] unknown privateKeyAlgorithm: '%s'", encAlgOid)
	}

	var kdf, cipher string

	// PBES1: pbeWithMD5AndDES-CBC -> KDF=PBKDF1, Cipher=DES-CBC.
	if strings.HasPrefix(encAlg, "pbeWith") {
		kdf = "PBKDF1"
		cipher = strings.Split(strings.ReplaceAll(encAlg, "pbeWith", ""), "And")[1]
	}

	// PBES2: separate KDF + EncryptionScheme algorithm identifiers.
	if encAlg == "PBES2" {
		var pbes2 pbes2Params
		if _, err := asn1.Unmarshal(epki.EncryptionAlgorithm.Parameters.FullBytes, &pbes2); err != nil {
			return nil, fmt.Errorf("[ERROR] PBES2 of PKCS#8 private key could not be parsed: '%s'", privKeyPath)
		}
		kdf = pbes2.KeyDerivationFunc.Algorithm.String()
		if name, ok := pkcs8OIDToAlgorithm[kdf]; ok {
			kdf = name
		}
		cipher = pbes2.EncryptionScheme.Algorithm.String()
		if name, ok := pkcs8OIDToAlgorithm[cipher]; ok {
			cipher = name
		}
	}

	return newPrivateKey(userName, pub, privKeyPath, "PKCS#8", kdf, cipher), nil
}

// pkcs8OIDToAlgorithm maps PKCS#8 encryption-related OIDs to their
// human-readable names. RFC 8018 covers the PBES1/PBES2/PBKDF2 entries;
// the AES variants come from NIST CSOR.
var pkcs8OIDToAlgorithm = map[string]string{
	// PBES1 (RFC 8018 §6.1)
	"1.2.840.113549.1.5.1":  "pbeWithMD2AndDES-CBC",
	"1.2.840.113549.1.5.4":  "pbeWithMD2AndRC2-CBC",
	"1.2.840.113549.1.5.3":  "pbeWithMD5AndDES-CBC",
	"1.2.840.113549.1.5.6":  "pbeWithMD5AndRC2-CBC",
	"1.2.840.113549.1.5.10": "pbeWithSHA1AndDES-CBC",
	"1.2.840.113549.1.5.11": "pbeWithSHA1AndRC2-CBC",
	// PBES2 outer
	"1.2.840.113549.1.5.13": "PBES2",
	// keyDerivationFunc
	"1.2.840.113549.1.5.12": "PBKDF2",
	// encryptionScheme — AES-{128,192,256}-CBC
	"2.16.840.1.101.3.4.1.2":  "aes128-CBC",
	"2.16.840.1.101.3.4.1.22": "aes192-CBC",
	"2.16.840.1.101.3.4.1.42": "aes256-CBC",
}

// parsePrivateKeyPEMEncrypted handles the legacy PEM-encrypted
// "RSA PRIVATE KEY" format (DEK-Info header). The cipher is the first
// comma-delimited field of DEK-Info; the KDF is always OpenSSL's
// EVP_BytesToKey.
func parsePrivateKeyPEMEncrypted(userName, privKeyPath, dekInfo string, pub publicKey) *privateKey {
	slog.Debug("parsePrivateKeyPEMEncrypted", "userName", userName, "privKeyPath", privKeyPath, "dekInfo", dekInfo)
	cipher := strings.Split(dekInfo, ",")[0]
	return newPrivateKey(userName, pub, privKeyPath, "PEM", "EVP_BytesToKey", cipher)
}
