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
	"strconv"
	"strings"
	"time"

	"github.com/RantaSec/golinhound/internal/opengraph"
	"golang.org/x/crypto/ssh"
)

// SSHClientCollector emits private-key artifacts for every local user.
type SSHClientCollector struct {
	// CollectExpiredCertificates: see Options.CollectExpiredCertificates.
	// Wired through to emitSSHCertificate so the expiry filter is
	// applied at the point where ValidBefore is already parsed.
	CollectExpiredCertificates bool
}

// Collect walks every user's ~/.ssh and emits SSHKeyPair nodes plus
// HasPrivateKey edges from the user to each parseable private key.
func (c *SSHClientCollector) Collect(ctx context.Context, h *Host, b *opengraph.GraphBuilder) error {
	for _, u := range h.Users {
		emitPrivateKeys(h, u, b, c.CollectExpiredCertificates)
	}
	return nil
}

// emitPrivateKeys adds a KeyPair node and a HasPrivateKey edge for every
// private key.
func emitPrivateKeys(h *Host, u *User, b *opengraph.GraphBuilder, collectExpiredCerts bool) {
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
				"PrivateKeyFile": pk.FilePath,
				"KeyFormat":      pk.KeyFormat,
				"KDF":            pk.KDF,
				"Cipher":         pk.Cipher,
				"Encrypted":      pk.Encrypted,
				"Comment":        pk.PublicKey.Comment,
			})

		emitSSHCertificate(h, u, pk, b, collectExpiredCerts)
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

// emitSSHCertificate emits the SSHCertificate node(s) and HasCertificate
// edge for the sibling `<privKeyFile>-cert.pub`, if one exists and
// passes the guards (parseable, vouches for this exact private key,
// not expired unless collectExpiredCerts is set).
func emitSSHCertificate(h *Host, u *User, pk *privateKey, b *opengraph.GraphBuilder, collectExpiredCerts bool) {
	certPath := pk.FilePath + "-cert.pub"
	cert, err := parseSSHCertificate(u.UserName, certPath)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Debug("emitSSHCertificate: could not parse sibling certificate", "certPath", certPath, "err", err)
		}
		return
	}
	if cert.SubjectKey.FingerprintSHA256 != pk.PublicKey.FingerprintSHA256 {
		slog.Debug("emitSSHCertificate: cert subject fingerprint does not match sibling private key",
			"certPath", certPath, "certSubjectFingerprint", cert.SubjectKey.FingerprintSHA256, "privKeyFingerprint", pk.PublicKey.FingerprintSHA256)
		return
	}
	if !collectExpiredCerts && rfc3339TimeIsPast(cert.ValidBefore) {
		slog.Debug("emitSSHCertificate: skipping expired certificate", "certPath", certPath, "validBefore", cert.ValidBefore)
		return
	}
	emitSSHCertificateNodes(b, h, u, pk, *cert)
}

// sshCertificate is the internal carrier for the signed portion of one
// OpenSSH user certificate. It does NOT correspond 1:1 to an
// SSHCertificate node - see emitSSHCertificateNodes below for the
// per-principal node-split workaround.
type sshCertificate struct {
	// --- node properties: signed-portion content, no on-disk context ---
	CertFingerprintSHA256 string // ssh.FingerprintSHA256(cert) - the CERT blob; shared across split nodes for the same cert
	CertFingerprintMD5    string // ssh.FingerprintLegacyMD5(cert)
	Serial                string // decimal; uint64 stringified to dodge JSON float64 precision loss
	KeyId                 string
	ValidPrincipals       []string          // full list as signed; ALWAYS non-nil (zero-length = wildcard per PROTOCOL.certkeys; null would fail BH ingest)
	ValidAfter            string            // RFC3339 UTC; lower-bound sentinel ValidAfter==0 -> "1970-01-01T00:00:00Z" (the epoch, unmodified)
	ValidBefore           string            // RFC3339 UTC; "never expires" sentinel ssh.CertTimeInfinity -> "9999-12-31T23:59:59Z"
	CriticalOptions       map[string]string // direct from ssh.Permissions
	Extensions            map[string]string
	CAFingerprintSHA256   string    // ssh.FingerprintSHA256(cert.SignatureKey) - the CA pubkey
	CAFingerprintMD5      string    // ssh.FingerprintLegacyMD5(cert.SignatureKey)
	SubjectKey            publicKey // the cert's subject pubkey (cert.Key); SubjectKey.FingerprintSHA256 == id of the SSHKeyPair this cert vouches for
	// --- edge properties: discovery context, NOT on the node ---
	UserName string
	FilePath string
}

// parseSSHCertificate reads an OpenSSH user certificate file
// (typically `<keyname>-cert.pub`) and extracts the signed portion into
// an sshCertificate. ssh.ParseAuthorizedKey returns a *ssh.Certificate
// when the key type is `*-cert-v01@openssh.com`; anything else is a
// misnamed file and an error. Host certs are rejected.
func parseSSHCertificate(userName, certPath string) (*sshCertificate, error) {
	slog.Debug("parseSSHCertificate", "userName", userName, "certPath", certPath)
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, fmt.Errorf("ssh.ParseAuthorizedKey: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%s: not an OpenSSH certificate (got %s)", certPath, pub.Type())
	}
	if cert.CertType != ssh.UserCert {
		return nil, fmt.Errorf("%s: not a user certificate (CertType=%d)", certPath, cert.CertType)
	}

	// Normalize the zero-principal (wildcard) case from nil to []string{}.
	principals := cert.ValidPrincipals
	if principals == nil {
		principals = []string{}
	}

	return &sshCertificate{
		CertFingerprintSHA256: strings.TrimPrefix(ssh.FingerprintSHA256(cert), "SHA256:"),
		CertFingerprintMD5:    ssh.FingerprintLegacyMD5(cert),
		Serial:                strconv.FormatUint(cert.Serial, 10),
		KeyId:                 cert.KeyId,
		ValidPrincipals:       principals,
		ValidAfter:            epochSecondsToRFC3339(cert.ValidAfter),
		ValidBefore:           epochSecondsToRFC3339(cert.ValidBefore),
		CriticalOptions:       cert.CriticalOptions,
		Extensions:            cert.Extensions,
		CAFingerprintSHA256:   strings.TrimPrefix(ssh.FingerprintSHA256(cert.SignatureKey), "SHA256:"),
		CAFingerprintMD5:      ssh.FingerprintLegacyMD5(cert.SignatureKey),
		SubjectKey:            *newPublicKey(cert.Key, ""), // Comment is per-host context; lives on HasPrivateKey, not the cert node
		UserName:              userName,
		FilePath:              certPath,
	}, nil
}

// epochSecondsToRFC3339 formats a Unix-epoch seconds value as RFC3339 UTC.
// The "never expires" sentinel (ssh.CertTimeInfinity per
// PROTOCOL.certkeys) collapses to the RFC3339 max; without that
// guard the int64(uint64) overflow at MaxInt64 would render it as
// 1969-12-31T23:59:59Z.
func epochSecondsToRFC3339(epoch uint64) string {
	if epoch == ssh.CertTimeInfinity {
		return "9999-12-31T23:59:59Z"
	}
	return time.Unix(int64(epoch), 0).UTC().Format(time.RFC3339)
}

// rfc3339TimeIsPast reports whether the given RFC3339 timestamp is in
// the past. Unparseable values return false and log a warning.
func rfc3339TimeIsPast(timestamp string) bool {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		slog.Warn("rfc3339TimeIsPast: could not parse RFC3339 timestamp; treating as not-past", "value", timestamp, "err", err)
		return false
	}
	return time.Now().UTC().After(t)
}

// emitSSHCertificateNodes emits one SSHCertificate node PER PRINCIPAL
// the certificate is valid for, plus one HasCertificate edge per node.
//
// ---- Why one node per principal ----
//
// WORKAROUND for a BloodHound OpenGraph limitation: as of v9.x rc, the
// `match_by: "property"` node-selector only supports the "equals"
// operator. There is no contains/in/any matcher. That means a single
// SSHCertificate node carrying ValidPrincipals=["alice","ops","oncall"]
// is unqueryable.
//
// Splitting the cert into one node per principal makes the data
// queryable today via ByProperty(SSHCertificate, PropEq("Principal",
// "ops")) at the cost of duplicating the signed-portion properties
// across N nodes.
//
// Wildcard ("valid for any principal") collapses to a SINGLE node with
// Principal="*".
//
// When BloodHound grows a richer matcher (contains/in/regex) this whole
// split can be reverted to a single node per cert and the Principal
// property removed.
func emitSSHCertificateNodes(b *opengraph.GraphBuilder, h *Host, u *User, pk *privateKey, c sshCertificate) {
	// Wildcard ("zero principals") certs collapse to one node with
	// Principal="*". Per PROTOCOL.certkeys, "a zero-length valid
	// principals field means the certificate is valid for any
	// principal of the specified type."
	principals := c.ValidPrincipals
	if len(principals) == 0 {
		principals = []string{"*"}
	}
	for _, principal := range principals {
		// id and name are both "<principal>@<cert fingerprint>"
		// (cert's own SHA256, not the CA's). The principal prefix
		// only exists because of the per-principal-split workaround
		// above - it's what gives each split node a distinct id while
		// the underlying cert fingerprint stays shared. Once BloodHound
		// grows a list-contains matcher and the split goes away, the
		// id can collapse to just CertFingerprintSHA256.
		nodeID := principal + "@" + c.CertFingerprintSHA256

		props := map[string]any{
			"name":                  nodeID,
			"Principal":             principal,                   // split-node primary key for BloodHound property-equals queries
			"WildcardPrincipal":     len(c.ValidPrincipals) == 0, // edge-matcher target for zero-principal/wildcard certs
			"CertFingerprintSHA256": c.CertFingerprintSHA256,
			"CertFingerprintMD5":    c.CertFingerprintMD5,
			"Serial":                c.Serial,
			"KeyId":                 c.KeyId,
			// ValidPrincipals is redundant while every node already carries the
			// per-principal Principal scalar. Re-enable once BloodHound gains a
			// list-contains matcher and the per-principal split can collapse
			// back to one node per cert.
			// "ValidPrincipals":       c.ValidPrincipals,
			"ValidAfter":          c.ValidAfter,
			"ValidBefore":         c.ValidBefore,
			"CAFingerprintSHA256": c.CAFingerprintSHA256,
			"CAFingerprintMD5":    c.CAFingerprintMD5,
			// Subject keypair properties (mirroring SSHKeyPair node properties)
			"SubjectAlgorithm":         c.SubjectKey.Algorithm,
			"SubjectFingerprintSHA256": c.SubjectKey.FingerprintSHA256,
			"SubjectFingerprintMD5":    c.SubjectKey.FingerprintMD5,
			"SubjectFIDO2":             c.SubjectKey.FIDO2,
		}
		// BloodHound's OpenGraph schema rejects map-shaped node
		// properties (only string/number/boolean/array allowed). Flatten
		// each cert option/extension into its own scalar property keyed
		// "CriticalOption_<name>" / "Extension_<name>".
		for k, v := range c.CriticalOptions {
			props["CriticalOption_"+k] = v
		}
		for k, v := range c.Extensions {
			props["Extension_"+k] = v
		}

		b.AddNode([]string{"SSHCertificate"}, nodeID, props)
		// HasCertificate edge payload mirrors HasPrivateKey: the same
		// key-protection properties (KeyFormat/KDF/Cipher/Encrypted/
		// Comment) come from the UNDERLYING private key, since the cert
		// is just a public-text envelope around that key.
		b.AddEdge("HasCertificate",
			opengraph.ByID("SSHUser", h.ReferenceUser(u.UID)),
			opengraph.ByID("SSHCertificate", nodeID),
			map[string]any{
				"PrivateKeyFile":  pk.FilePath,
				"CertificateFile": c.FilePath,
				"KeyFormat":       pk.KeyFormat,
				"KDF":             pk.KDF,
				"Cipher":          pk.Cipher,
				"Encrypted":       pk.Encrypted,
				"Comment":         pk.PublicKey.Comment,
			})
	}
}
