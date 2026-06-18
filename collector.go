package golinhound

import (
	"bufio"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/shirou/gopsutil/v4/process"
	"golang.org/x/crypto/ssh"
)

const (
	AzureIMDSTimeout           = 3 * time.Second
	CredentialCacheLoadTimeout = 3 * time.Second
	KeytabFindTimeout          = 5 * time.Second
	KeytabLoadTimeout          = 3 * time.Second
	SSHDExecTimeout            = 2 * time.Second
	SSHExecTimeout             = 2 * time.Second
	SudoExecTimeout            = 2 * time.Second
)

type LinhoundCollector struct {
	sshdConfig map[string]string
	computer   *Computer
}

// NewLinHoundCollector creates a new LinhoundCollector object and loads the current systems metadata and SSHD config
func NewLinhoundCollector() *LinhoundCollector {
	// exit if not Linux
	if runtime.GOOS != "linux" {
		log.Fatalf("[ERROR] This program only works on Linux.")
	}
	// exit with an error if not running as root
	if os.Geteuid() != 0 {
		log.Fatalf("[ERROR] This program must run as root.")
	}
	sshdConfig := loadSSHDConfig()
	computer := loadComputerData()
	c := LinhoundCollector{sshdConfig, computer}
	return &c
}

// hasSSHD reports whether this host runs an SSH server. Server-side artifacts
// (authorized_keys consumed by sshd, forwarded-agent sockets created by inbound
// sshd sessions) only exist on hosts where sshd is installed.
func (l LinhoundCollector) hasSSHD() bool {
	return l.sshdConfig != nil
}

// loadSSHDConfig parses the current SSHD config from "sshd -T". Returns nil
// when sshd is not installed or the command fails, signalling that the
// collector is running on an SSH-client-only system.
func loadSSHDConfig() map[string]string {
	logVerbose("loadSSHDConfig()\n")
	// create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), SSHDExecTimeout)
	defer cancel()

	// retrieve effective sshd config; if sshd is not installed or the command
	// fails, treat this host as SSH client only and skip server-side routines
	cmd := exec.CommandContext(ctx, "sshd", "-T")
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		logVerbose("loadSSHDConfig(): 'sshd -T' failed (%v); treating host as SSH client only\n", err)
		return nil
	}

	// store effective sshd config in map (key -> value, without the key prefix)
	sshdConfig := make(map[string]string)
	for line := range strings.SplitSeq(out.String(), "\n") {
		key, value, _ := strings.Cut(line, " ")
		sshdConfig[key] = value
	}
	return sshdConfig
}

// loadComputerData retrieves the host FQDN and derives a unique device id from the "/etc/machine-id"
func loadComputerData() *Computer {
	logVerbose("loadComputerData()\n")
	// read unique machine-id
	file, err := os.Open("/etc/machine-id")
	if err != nil {
		log.Fatalf("[ERROR] file '/etc/machine-id' could not be opened.")
	}
	defer file.Close()
	machineId := make([]byte, 32)
	file.Read(machineId)

	// derive a unique id from it using an HMAC
	hmac := hmac.New(sha256.New, []byte("fLhn74XaBtmouSQkBSRIAm6tbISvrf26"))
	hmac.Write(machineId)
	uniqueId := strings.TrimRight(base64.StdEncoding.EncodeToString(hmac.Sum(nil)), "=")

	// query the fqdn of the host
	fqdn, err := os.Hostname()
	if err != nil {
		log.Fatalf("[ERROR] hostname could not be retrieved.")
	}

	// lookup the user name of the root user
	root, err := user.LookupId("0")
	if err != nil {
		log.Fatalf("[ERROR] uid=0 could not be resolved.")
	}

	return NewComputer(uniqueId, fqdn, root.Username)
}

// parsePublicKey returns a PublicKey for a given public key string
func (l LinhoundCollector) parsePublicKey(keyLine string) (*PublicKey, error) {
	logVerbose("parsePublicKey(keyLine=%s)\n", strings.TrimSpace(keyLine))
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		return nil, fmt.Errorf("[ERROR] public key does not match the expected format: %s", strings.TrimSpace(keyLine))
	}

	publicKey, err := NewPublicKey(base64.StdEncoding.EncodeToString(key.Marshal()), comment)
	return publicKey, err
}

// parsePrivateKeyOpenSSH parses an OpenSSH private key and returns a PrivateKey
func (l LinhoundCollector) parsePrivateKeyOpenSSH(userName string, privKeyPath string, privKeyRaw []byte) (*PrivateKey, error) {
	logVerbose("parsePrivateKeyOpenSSH(userName=%s, privKeyPath=%s)\n", userName, privKeyPath)
	// https://github.com/golang/crypto/blob/8f580defa01dec23898d3cd27f6369cdcc62f71f/ssh/keys.go#L1442
	const privateKeyAuthMagic = "openssh-key-v1\x00"
	// https://github.com/golang/crypto/blob/8f580defa01dec23898d3cd27f6369cdcc62f71f/ssh/keys.go#L1447
	type openSSHEncryptedPrivateKey struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	// https://github.com/golang/crypto/blob/8f580defa01dec23898d3cd27f6369cdcc62f71f/ssh/keys.go#L1494
	if len(privKeyRaw) < len(privateKeyAuthMagic) || string(privKeyRaw[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return nil, fmt.Errorf("[ERROR] '%s' not a valid OpenSSH private key", privKeyPath)
	}
	remaining := privKeyRaw[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return nil, fmt.Errorf("[ERROR] OpenSSH private key unmarshal failed: '%s' ", privKeyPath)
	}

	// verify and extract the embedded public key
	publicKey, err := NewPublicKey(base64.StdEncoding.EncodeToString(w.PubKey), "")
	if err != nil {
		return nil, err
	}

	return NewPrivateKey(*l.computer, userName, *publicKey, privKeyPath, "openssh-key-v1", w.KdfName, w.CipherName), nil
}

// parsePrivateKeyUnencrypted parses unencrypted PEM & PKCS#8 keys and returns a PrivateKey
func (l LinhoundCollector) parsePrivateKeyUnencrypted(userName string, privKeyPath string, pemBytes []byte, keyFormat string) (*PrivateKey, error) {
	logVerbose("parsePrivateKeyUnencrypted(userName=%s, privKeyPath=%s, keyFormat=%s)\n", userName, privKeyPath, keyFormat)
	// Crypto.PrivateKey always implements Public()
	type withPublic interface {
		Public() crypto.PublicKey
	}
	// parse private key bytes
	cryptoPrivKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] unencrypted PKCS#8 key could not be parsed: '%s'", privKeyPath)
	}
	// extract public key from private key
	pub, err := ssh.NewPublicKey(cryptoPrivKey.(withPublic).Public())
	if err != nil {
		return nil, fmt.Errorf("[ERROR] corresponding PKCS#8 public key could not be calculated: '%s'", privKeyPath)
	}
	// marshal and parse the public key
	pubBytes := ssh.MarshalAuthorizedKey(pub)
	pubKey, _ := l.parsePublicKey(string(pubBytes))

	return NewPrivateKey(*l.computer, userName, *pubKey, privKeyPath, keyFormat, "none", "none"), nil
}

// parsePrivateKetPKCS8Encrypted parses encrypted PKCS#8 private key
func (l LinhoundCollector) parsePrivateKeyPKCS8Encrypted(userName string, privateKeyPath string, privateKeyBytes []byte, publicKey PublicKey) (*PrivateKey, error) {
	logVerbose("parsePrivateKeyPKCS8Encrypted(userName=%s, privKeyPath=%s)\n", userName, privateKeyPath)
	// https://www.rfc-editor.org/rfc/rfc5208#appendix-A
	type encryptedPrivateKeyInfo struct {
		EncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedData       []byte
	}
	// https://www.rfc-editor.org/rfc/rfc8018#appendix-C
	type pbes2Params struct {
		KeyDerivationFunc pkix.AlgorithmIdentifier
		EncryptionScheme  pkix.AlgorithmIdentifier
	}
	// https://www.rfc-editor.org/rfc/rfc8018
	var oidToAlgorithm = map[string]string{
		// EncryptedPrivateKeyInfo
		"1.2.840.113549.1.5.1":  "pbeWithMD2AndDES-CBC",
		"1.2.840.113549.1.5.4":  "pbeWithMD2AndRC2-CBC",
		"1.2.840.113549.1.5.3":  "pbeWithMD5AndDES-CBC",
		"1.2.840.113549.1.5.6":  "pbeWithMD5AndRC2-CBC",
		"1.2.840.113549.1.5.10": "pbeWithSHA1AndDES-CBC",
		"1.2.840.113549.1.5.11": "pbeWithSHA1AndRC2-CBC",
		"1.2.840.113549.1.5.13": "PBES2",
		// keyDerivationFunc
		"1.2.840.113549.1.5.12": "PBKDF2",
		// encryptionScheme
		"2.16.840.1.101.3.4.1.2":  "aes128-CBC",
		"2.16.840.1.101.3.4.1.22": "aes192-CBC",
		"2.16.840.1.101.3.4.1.42": "aes256-CBC",
	}

	// parse EncryptedPrivateKeyInfo
	var privKeyInfo encryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(privateKeyBytes, &privKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("[ERROR] EncryptedPrivateKeyInfo of PKCS#8 private key could not be parsed: '%s'", privateKeyPath)
	}

	// parse EncryptionAlgorithm
	encAlgOid := privKeyInfo.EncryptionAlgorithm.Algorithm.String()
	if _, ok := oidToAlgorithm[encAlgOid]; !ok {
		return nil, fmt.Errorf("[ERROR] unknown privateKeyAlgorithm:'%s", encAlgOid)
	}
	encAlg := oidToAlgorithm[encAlgOid]

	// prepare variables for key meta data
	var kdf, cipher string

	// handle PBES1 keys
	if strings.HasPrefix(encAlg, "pbeWith") {
		kdf = "PBKDF1"
		cipher = strings.Split(strings.ReplaceAll(encAlg, "pbeWith", ""), "And")[1]
	}

	// handle PBES2 keys
	if encAlg == "PBES2" {
		var pbes2 pbes2Params
		_, err := asn1.Unmarshal(privKeyInfo.EncryptionAlgorithm.Parameters.FullBytes, &pbes2)
		if err != nil {
			return nil, fmt.Errorf("[ERROR] PBES2 of PKCS#8 private key could not be parsed: '%s'", privateKeyPath)
		}

		// resolve kdf oid. if it fails, use oid as kdf string
		kdf = pbes2.KeyDerivationFunc.Algorithm.String()
		if _, ok := oidToAlgorithm[kdf]; ok {
			kdf = oidToAlgorithm[kdf]
		}

		// resolve cipher oid. if it fails, use oid as cipher string
		cipher = pbes2.EncryptionScheme.Algorithm.String()
		if _, ok := oidToAlgorithm[cipher]; ok {
			cipher = oidToAlgorithm[cipher]
		}
	}

	return NewPrivateKey(*l.computer, userName, publicKey, privateKeyPath, "PKCS#8", kdf, cipher), nil
}

// parsePrivateKeyPEMEncrypted parses encrypted PEM private key
func (l LinhoundCollector) parsePrivateKeyPEMEncrypted(userName string, privateKeyPath string, dekInfo string, publicKey PublicKey) *PrivateKey {
	logVerbose("parsePrivateKeyPEMEncrypted(userName=%s, privKeyPath=%s, dekInfo=%s)\n", userName, privateKeyPath, dekInfo)
	cipher := strings.Split(dekInfo, ",")[0]
	return NewPrivateKey(*l.computer, userName, publicKey, privateKeyPath, "PEM", "EVP_BytesToKey", cipher)
}

// privateKeysFiles returns a list of potential private key files in the specified user home directory
func (l LinhoundCollector) privateKeysFiles(userDir string) []string {
	logVerbose("privateKeysFiles(userDir=%s)\n", userDir)
	globPattern := filepath.Join(userDir, "/.ssh/*")
	keyFilesCandidates, err := filepath.Glob(globPattern)
	if err != nil {
		logVerbose("privateKeysFiles(userDir=%s): Invalid glob pattern\n", userDir)
	}
	// filter out files that are obviously not private keys
	var keyFiles []string
	for _, keyFile := range keyFilesCandidates {
		if strings.HasSuffix(keyFile, ".pub") || strings.HasSuffix(keyFile, "/config") || strings.HasSuffix(keyFile, "/known_hosts") || strings.HasSuffix(keyFile, "/authorized_keys") || strings.HasSuffix(keyFile, "/authorized_keys2") {
			continue
		}
		keyFiles = append(keyFiles, keyFile)
	}

	return keyFiles
}

// authorizedKeysFiles retrieve all authorized keys files for a given user
func (l LinhoundCollector) authorizedKeysFiles(userName string, userDir string) []string {
	logVerbose("authorizedKeysFiles(userName=%s, userDir=%s)\n", userName, userDir)
	configValues := strings.Fields(l.sshdConfig["authorizedkeysfile"])

	var authKeysFiles []string
	for _, authKeyFile := range configValues {
		// replace username/homedir placeholders
		authKeyFile = strings.ReplaceAll(authKeyFile, "%u", userName)
		authKeyFile = strings.ReplaceAll(authKeyFile, "%h", userDir+"/")
		// if the path is relative, prepend homedir
		if !filepath.IsAbs(authKeyFile) {
			authKeyFile = filepath.Join(userDir, authKeyFile)
		}
		// if the path is a file and has not been seen before, add it to our list
		fileInfo, err := os.Stat(authKeyFile)
		if err == nil && !fileInfo.IsDir() && !slices.Contains(authKeysFiles, authKeyFile) {
			authKeysFiles = append(authKeysFiles, authKeyFile)
		}
	}

	return authKeysFiles
}

// queryOpenSockets monitors for SSH agent sockets that are currently open and writes them into the channel chSockets
func queryOpenSockets(chSockets chan<- string, wg *sync.WaitGroup) {
	logVerbose("queryOpenSockets()\n")
	defer wg.Done()

	sockets, _ := filepath.Glob("/tmp/ssh-*/agent.*")
	for _, socket := range sockets {
		chSockets <- socket
	}
}

// watchNewSockets monitors for new SSH agent sockets and writes them into the channel chSockets
func watchNewSockets(chSockets chan<- string, duration int, wg *sync.WaitGroup) {
	logVerbose("watchNewSockets(duration=%d)\n", duration)
	defer wg.Done()

	// stop waiting for new forwarded keys, if time limit has passed
	timeout := time.After(time.Duration(duration) * time.Minute)

	// set up new watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Println("[ERROR] file system watcher could not be initialized. No new forwarded keys will be collected.")
		log.Println(err)
		return
	}
	defer watcher.Close()

	// watch /tmp/ directory
	err = watcher.Add("/tmp/")
	if err != nil {
		log.Println("[ERROR] directory 'tmp' could not be watched. No new forwarded keys will be collected.")
		log.Println(err)
		return
	}

	// loop until error occurs / time limit is reached
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Create) && strings.HasPrefix(event.Name, "/tmp/ssh-") {
				sockets, _ := filepath.Glob(filepath.Join(event.Name, "/agent.*"))
				for _, socket := range sockets {
					chSockets <- socket
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[ERROR] fsnotify: %v\n", err)
		case <-timeout:
			return
		}
	}
}

// isInteractiveShell returns true if a given shell is an interactive shell and false if it is non-interactive
func isInteractiveShell(shell string) bool {
	shellName := filepath.Base(shell)
	switch shellName {
	case "nologin", "false", "true", "sync":
		return false
	default:
		return true
	}
}

// isRootLoginAllowed returns true, if the root user is allowed to login to the current computer with an SSH keypair.
func (l LinhoundCollector) isRootLoginAllowed() bool {
	switch l.sshdConfig["permitrootlogin"] {
	case "yes", "without-password", "prohibit-password":
		return true
	default:
		return false
	}
}

// findKeytabFiles searches maxDepth deep through rootDir and writes all .keytab files into chKeytabs
func findKeytabFiles(ctx context.Context, wg *sync.WaitGroup, chKeytabs chan<- string, rootDir string, maxDepth int) {
	defer wg.Done()
	rootDir = filepath.Clean(rootDir)
	rootDepth := strings.Count(rootDir, string(os.PathSeparator))

	err := filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
		// ignore errors
		if err != nil {
			return nil
		}

		// respect timeout
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// add max depth
		currDepth := strings.Count(path, string(os.PathSeparator)) - rootDepth
		if currDepth > maxDepth && d.IsDir() {
			return filepath.SkipDir
		}

		// print findings
		if !d.IsDir() && filepath.Ext(d.Name()) == ".keytab" {
			chKeytabs <- path
		}

		return nil
	})

	if err != nil {
		log.Printf("[ERROR] WalkDir(root=%s, maxDepth=%d): %v\n", rootDir, maxDepth, err)
	}
}

// loadKeytab parses a given keytab file with a timeout
func loadKeytab(ctx context.Context, filePath string) (*keytab.Keytab, error) {
	type result struct {
		keytab *keytab.Keytab
		err    error
	}

	resultChan := make(chan result, 1)

	go func() {
		kt, err := keytab.Load(filePath)
		resultChan <- result{keytab: kt, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.keytab, res.err
	}
}

// findFileTicketCaches finds paths of kerberos ticket caches
// TODO add uid parsing
// TODO add *.ccache files
func findFileTicketCaches() []string {
	var caches []string
	caches1, _ := filepath.Glob("/tmp/krb5cc*")
	caches = append(caches, caches1...)
	caches2, _ := filepath.Glob("/run/user/*/krb5cc/*")
	caches = append(caches, caches2...)
	return caches
}

// loadCCache parses file-based kerberos ticket caches with a timeout
func loadCCache(ctx context.Context, filePath string) (*credentials.CCache, error) {
	// check if file is empty, because LoadCCache panics otherwise
	fi, err := os.Stat(filePath)
	if err != nil || fi.Size() == 0 {
		return nil, fmt.Errorf("file is empty: %s", filePath)
	}

	type result struct {
		ccache *credentials.CCache
		err    error
	}
	resultChan := make(chan result, 1)

	go func() {
		ccache, err := credentials.LoadCCache(filePath)
		resultChan <- result{ccache: ccache, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultChan:
		return res.ccache, res.err
	}
}

// findKeyringTicketCaches finds paths of kernel keyring ticket caches
// https://github.com/TarlogicSecurity/tickey
// TODO not yet implemented
func findKeyringTicketCaches() []string {
	return []string{}
}

// findKCMTicketCaches finds paths of SSSD Kerberos Cache Manager ticket caches
// https://github.com/mandiant/SSSDKCMExtractor
// TODO not yet implemented
func findKCMTicketCaches() []string {
	kerbCacheManagerDB := "/var/lib/sss/secrets/secrets.ldb"
	if _, err := os.Stat(kerbCacheManagerDB); err == nil {
		logVerbose("[NOT IMPLEMENTED] Kerberos tickets from %s cannot be extracted: function not implemented\n", kerbCacheManagerDB)
	}
	return []string{}
}

// azureIMDS queries the Azure Instance Metadata Service endpoint specified in path and returns its output
func azureIMDS(path string) ([]byte, error) {
	client := &http.Client{
		Timeout: AzureIMDSTimeout,
	}

	// Create the request with the necessary headers
	url := fmt.Sprintf("http://169.254.169.254/metadata/%s?api-version=2025-04-07", path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}
	req.Header.Add("Metadata", "true")

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// azureIMDSIdentityInfo returns the output of /metadata/identity/info as a struct
func azureIMDSIdentityInfo() (*metadataIdentityInfo, error) {
	body, err := azureIMDS("identity/info")
	if err != nil {
		return nil, err
	}

	var md metadataIdentityInfo
	err = json.Unmarshal(body, &md)
	if err != nil {
		return nil, err
	}
	return &md, nil
}

// azureIMDSInstanceCompute returns the output of /metadata/instance/compute as a struct
func azureIMDSInstanceCompute() (*metadataInstanceCompute, error) {
	body, err := azureIMDS("instance/compute")
	if err != nil {
		return nil, err
	}

	var md metadataInstanceCompute
	err = json.Unmarshal(body, &md)
	if err != nil {
		return nil, err
	}
	return &md, nil
}

// ForwardedKeys collects key information from all SSH agent sockets for the next 'duration' minutes
func (l LinhoundCollector) ForwardedKeys(duration int) []*ForwardedKey {
	logVerbose("ForwardedKeys(duration=%d)\n", duration)
	var forwardedKeys []*ForwardedKey
	// create channel that closes after both collection goroutines have finished
	chSockets := make(chan string)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		wg.Wait()
		close(chSockets)
	}()

	// run the goroutines
	go queryOpenSockets(chSockets, &wg)
	go watchNewSockets(chSockets, duration, &wg)

	// parse the results
	for socket := range chSockets {
		// create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), SSHExecTimeout)

		// retrieve public keys from socket
		cmd := exec.CommandContext(ctx, "ssh-add", "-L")
		cmd.Env = []string{"SSH_AUTH_SOCK=" + socket}
		stdOut, err := cmd.Output()
		cancel()
		if err != nil {
			logVerbose("ForwardedKeys(duration=%d): Public key could not be retrieved from socket: %s\n", duration, socket)
			continue
		}

		// access respective sshd process
		sshdPid, _ := strconv.ParseInt(strings.Split(filepath.Base(socket), ".")[1], 10, 32)
		sshdProcess, err := process.NewProcess(int32(sshdPid))
		if err != nil {
			logVerbose("ForwardedKeys(duration=%d): SSHD process with PID %d no longer exists\n", duration, sshdPid)
			continue
		}

		// retrieve username
		sshdUser, err := sshdProcess.Username()
		if err != nil {
			logVerbose("ForwardedKeys(duration=%d): Owner of SSHD process with PID %d could not be determined\n", duration, sshdPid)
			continue
		}

		// retrieve SSH session information
		sshdChildProcesses, err := sshdProcess.Children()
		if err != nil || len(sshdChildProcesses) == 0 {
			logVerbose("ForwardedKeys(duration=%d): SSHD process with PID %d does not have any children\n", duration, sshdPid)
			continue
		}
		loginTimeEpoch, _ := sshdChildProcesses[0].CreateTime()
		loginTimeZulu := time.Unix(loginTimeEpoch/1000, 0).UTC().Format(time.RFC3339)

		var loginIp string
		sshdChildEnviron, _ := sshdChildProcesses[0].Environ()
		for _, envString := range sshdChildEnviron {
			if strings.Contains(envString, "SSH_CONNECTION") {
				loginIp = strings.Split(strings.Split(envString, "=")[1], " ")[0]
			}
		}

		// the output of 'ssh-add -L' contains one public key per line
		for line := range strings.SplitSeq(strings.TrimSpace(string(stdOut)), "\n") {
			publicKey, _ := l.parsePublicKey(line)
			forwardedKeys = append(forwardedKeys, NewForwardedKey(*l.computer, sshdUser, *publicKey, socket, loginTimeZulu, loginIp))
		}
	}
	return forwardedKeys
}

// PrivateKeys retrieves all private keys for a given user
func (l LinhoundCollector) PrivateKeys(userName string) []*PrivateKey {
	logVerbose("PrivateKeys(userName=%s)\n", userName)
	// look up user data
	user, err := user.Lookup(userName)
	if err != nil {
		log.Printf("[ERROR] lookup for user '%s' failed. Private keys for user could not be collected.\n", userName)
		return []*PrivateKey{}
	}

	privKeyFiles := l.privateKeysFiles(user.HomeDir)

	var privKeys []*PrivateKey
	for _, privKeyFile := range privKeyFiles {
		pemBytes, err := os.ReadFile(privKeyFile)
		if err != nil {
			logVerbose("PrivateKeys(userName=%s): '%s' could not be opened\n", userName, privKeyFile)
			continue
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			logVerbose("PrivateKeys(userName=%s): Potential private key '%s' could not be decoded\n", userName, privKeyFile)
			continue
		}

		// handle OpenSSH keys (they always contain unencrypted public key)
		if block.Type == "OPENSSH PRIVATE KEY" {
			privKey, _ := l.parsePrivateKeyOpenSSH(userName, privKeyFile, block.Bytes)
			if privKey != nil {
				privKeys = append(privKeys, privKey)
				logVerbose("PrivateKeys(userName=%s): '%s' is an OpenSSH private key\n", userName, privKeyFile)
			}
			continue
		}
		// handle unencrypted PKCS#8 key
		if block.Type == "PRIVATE KEY" {
			privKey, _ := l.parsePrivateKeyUnencrypted(userName, privKeyFile, pemBytes, "PKCS#8")
			if privKey != nil {
				privKeys = append(privKeys, privKey)
				logVerbose("PrivateKeys(userName=%s): '%s' is an unencrypted PKCS#8 private key\n", userName, privKeyFile)
			}
			continue
		}
		// handle unencrypted PEM key
		if _, ok := block.Headers["DEK-Info"]; block.Type == "RSA PRIVATE KEY" && !ok {
			privKey, _ := l.parsePrivateKeyUnencrypted(userName, privKeyFile, pemBytes, "PEM")
			if privKey != nil {
				privKeys = append(privKeys, privKey)
				logVerbose("PrivateKeys(userName=%s): '%s' is an unencrypted PEM private key\n", userName, privKeyFile)
			}
			continue
		}

		// for all other formats, check if corresponding public key exists
		pubKeyFile := privKeyFile + ".pub"
		pubKeyBytes, err := os.ReadFile(pubKeyFile)
		if err != nil {
			logVerbose("PrivateKeys(userName=%s): Public key '%s' could not be read\n", userName, pubKeyFile)
			continue
		}
		pubKey, err := l.parsePublicKey(string(pubKeyBytes))
		if err != nil {
			logVerbose("%v\n", err)
			continue
		}

		// handle encrypted PKCS#8 key
		if block.Type == "ENCRYPTED PRIVATE KEY" {
			privKey, _ := l.parsePrivateKeyPKCS8Encrypted(userName, privKeyFile, block.Bytes, *pubKey)
			if privKey != nil {
				privKeys = append(privKeys, privKey)
				logVerbose("PrivateKeys(userName=%s): '%s' is an encrypted PKCS#8 private key\n", userName, privKeyFile)
			}
			continue
		}
		// handle encrypted PEM key
		if val, ok := block.Headers["DEK-Info"]; block.Type == "RSA PRIVATE KEY" && ok {
			privKey := l.parsePrivateKeyPEMEncrypted(userName, privKeyFile, val, *pubKey)
			privKeys = append(privKeys, privKey)
			logVerbose("PrivateKeys(userName=%s): '%s' is an encrypted PEM private key\n", userName, privKeyFile)
			continue
		}
	}

	return privKeys
}

// AuthorizedKeys retrieves all authorized keys for a given user
func (l LinhoundCollector) AuthorizedKeys(userName string) []*AuthorizedKey {
	logVerbose("AuthorizedKeys(userName=%s)\n", userName)
	// look up user data
	user, err := user.Lookup(userName)
	if err != nil {
		log.Printf("[ERROR] AuthorizedKeys(userName=%s): lookup for user '%s' failed\n", userName, userName)
		return []*AuthorizedKey{}
	}

	authKeysFiles := l.authorizedKeysFiles(userName, user.HomeDir)

	var authKeys []*AuthorizedKey
	for _, authKeysFile := range authKeysFiles {
		// open authorized keys file
		file, err := os.Open(authKeysFile)
		if err != nil {
			log.Printf("[ERROR] AuthorizedKeys(userName=%s): '%s' could not be opened\n", userName, authKeysFile)
			return []*AuthorizedKey{}
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)
		fileScanner.Split(bufio.ScanLines)

		// parse non-empty lines
		for fileScanner.Scan() {
			if line := strings.TrimSpace(fileScanner.Text()); line != "" {
				publicKey, err := l.parsePublicKey(line)
				if err != nil {
					log.Println(err)
					continue
				}
				authKey := newAuthorizedKey(*l.computer, userName, publicKey, authKeysFile)
				authKeys = append(authKeys, authKey)
			}
		}
	}
	return authKeys
}

// Sudoer returns a list of a sudoer object if the specified user has sudo privileges
func (l LinhoundCollector) Sudoer(userName string) []*Sudoer {
	// verify user exists and is not root
	if user, err := user.Lookup(userName); err != nil || user.Uid == "0" {
		logVerbose("Sudoer(userName=%s): user is root or could not be resolved\n", userName)
		return []*Sudoer{}
	}

	// create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), SudoExecTimeout)
	defer cancel()

	// retrieve effective sshd config
	cmd := exec.CommandContext(ctx, "sudo", "-S", "-n", "-l", "-U", userName)
	stdOut, err := cmd.Output()
	if err != nil {
		log.Printf("[ERROR] command 'sudo -S -n -l -U %s' could not be executed.\n", userName)
		return []*Sudoer{}
	}

	if strings.Contains(string(stdOut), "may run the following commands on") {
		// remove unnecessary text and whitespaces from putput
		commands := regexp.MustCompile(`(?s).* may run the following commands on \S+:`).ReplaceAllString(string(stdOut), "")
		commands = regexp.MustCompile(`(?m)^\s+|^\s+$`).ReplaceAllString(commands, "")
		commands = strings.TrimSpace(commands)
		// check if user requires password to run arbitrary commands
		if strings.Contains(commands, "(ALL : ALL) NOPASSWD: ALL") || strings.Contains(commands, "(ALL) NOPASSWD: ALL") {
			return []*Sudoer{newSudoer(*l.computer, userName, false, commands)}
		}
		if strings.Contains(commands, "(ALL : ALL) ALL") || strings.Contains(commands, "(ALL) ALL") {
			return []*Sudoer{newSudoer(*l.computer, userName, true, commands)}
		}
	}
	return []*Sudoer{}
}

// Keytabs retrieves keytabs from the local computer
func (l LinhoundCollector) Keytabs() []*Keytab {
	// add timeout to keytab searches
	ctx, cancel := context.WithTimeout(context.Background(), KeytabFindTimeout)
	defer cancel()
	// wait group to wait for go routines to finish
	var wg sync.WaitGroup
	// output channel
	chKeytabs := make(chan string)

	// search keytab files
	wg.Add(2)
	go findKeytabFiles(ctx, &wg, chKeytabs, "/etc/", 2)
	go findKeytabFiles(ctx, &wg, chKeytabs, "/home/", 1)

	// closer routine
	go func() {
		wg.Wait()
		close(chKeytabs)
	}()

	// output
	var keytabs []*Keytab
	for file := range chKeytabs {
		ctx2, cancel2 := context.WithTimeout(context.Background(), KeytabLoadTimeout)
		kt, err := loadKeytab(ctx2, file)
		cancel2()
		if err != nil {
			log.Printf("[ERROR] Could not load keytab '%s': %v\n", file, err)
			continue
		}

		for _, entry := range kt.Entries {
			keytabs = append(keytabs, &Keytab{
				Computer:        *l.computer,
				FilePath:        file,
				ClientPrincipal: entry.Principal.String(),
				ClientRealm:     entry.Principal.Realm,
			})
		}
	}
	return keytabs
}

// TGTs retrieves all TGTs from local ticket caches
func (l LinhoundCollector) TGTs() []*TGT {
	var tickets []*TGT
	cacheFiles := findFileTicketCaches()

	for _, cacheFile := range cacheFiles {
		// check if file is empty, because LoadCCache panics otherwise
		fi, err := os.Stat(cacheFile)
		if err != nil || fi.Size() == 0 {
			continue
		}

		// set load timeout
		ctx, cancel := context.WithTimeout(context.Background(), CredentialCacheLoadTimeout)

		// Load ticket cache
		ccache, err := loadCCache(ctx, cacheFile)
		cancel()
		if err != nil {
			log.Printf("[ERROR] Could not load Kerberos ticket cache '%s': %v\n", cacheFile, err)
			continue
		}

		for _, creds := range ccache.Credentials {
			// ticket not a TGT
			if !strings.HasPrefix(creds.Server.PrincipalName.PrincipalNameString(), "krbtgt/") {
				continue
			}
			//ticket expired and non-renewable
			if now := time.Now(); now.After(creds.EndTime) && now.After(creds.RenewTill) {
				continue
			}

			tickets = append(tickets, &TGT{
				Computer:        *l.computer,
				FilePath:        cacheFile,
				ClientPrincipal: creds.Client.PrincipalName.PrincipalNameString(),
				ClientRealm:     creds.Client.Realm,
				StartTime:       creds.StartTime.UTC().Format(time.RFC3339),
				EndTime:         creds.EndTime.UTC().Format(time.RFC3339),
				RenewTime:       creds.RenewTill.UTC().Format(time.RFC3339),
			})
		}
	}

	// TODO not implemented
	findKCMTicketCaches()
	findKeyringTicketCaches()

	return tickets
}

// AzureVM retrieves information from Azure IMDS
func (l LinhoundCollector) AzureVM() []*AZVM {
	var azvms []*AZVM

	mdInstanceCompute, err := azureIMDSInstanceCompute()
	if err != nil {
		logVerbose("%v", err)
		return azvms
	}

	mdIdentityInfo, err := azureIMDSIdentityInfo()
	if err != nil {
		logVerbose("%v", err)
		return azvms
	}

	azvms = append(azvms, &AZVM{
		Computer:        *l.computer,
		TenantId:        mdIdentityInfo.TenantId,
		ResourceId:      mdInstanceCompute.ResourceId,
		Name:            mdInstanceCompute.Name,
		OperatingSystem: mdInstanceCompute.OSType,
	})

	return azvms
}

// CollectArtifacts iterates over all local users and searches for respective
// authorized keys, private keys, forwarded agents and sudoer privileges.
func (l LinhoundCollector) CollectArtifacts(duration int) ([]*Sudoer, []*PrivateKey, []*ForwardedKey, []*AuthorizedKey, []*Keytab, []*TGT, []*AZVM) {
	// read /etc/passwd to interate over local users
	passwdBytes, err := os.ReadFile("/etc/passwd")
	if err != nil {
		log.Fatalf("[ERROR] /etc/passwd could not be read")
	}
	// prepare slices for return values
	var fwdKeys []*ForwardedKey
	var authKeys []*AuthorizedKey
	var privKeys []*PrivateKey
	var sudoers []*Sudoer
	var keytabs []*Keytab
	var tgts []*TGT
	var azvms []*AZVM

	// always query Azure IMDS, keytabs and TGTs (independent of sshd)
	azvms = l.AzureVM()
	keytabs = l.Keytabs()
	tgts = l.TGTs()

	// forwarded-agent sockets only exist for inbound sshd sessions
	if l.hasSSHD() {
		fwdKeys = l.ForwardedKeys(duration)
	} else {
		logVerbose("CollectArtifacts: sshd not installed, skipping ForwardedKeys collection\n")
	}

	for passwdLine := range strings.SplitSeq(string(passwdBytes), "\n") {
		passwdEntry := strings.Split(passwdLine, ":")
		// skip comments and invalid lines
		if strings.HasPrefix(passwdLine, "#") || len(passwdEntry) != 7 {
			continue
		}
		pwName := passwdEntry[0]
		pwUid := passwdEntry[2]
		pwShell := passwdEntry[6]

		// always add sudoers, private keys
		sudoers = append(sudoers, l.Sudoer(pwName)...)
		privKeys = append(privKeys, l.PrivateKeys(pwName)...)

		// authorized_keys are consumed by sshd, so they are only meaningful on
		// hosts that actually run an SSH server
		if !l.hasSSHD() {
			continue
		}
		// skip authorized keys if user doesn't have interactive shell
		if !isInteractiveShell(pwShell) {
			continue
		}
		// skip authorized keys if user is root and root login is denied
		if pwUid == "0" && !l.isRootLoginAllowed() {
			continue
		}
		authKeys = append(authKeys, l.AuthorizedKeys(pwName)...)
	}

	return sudoers, privKeys, fwdKeys, authKeys, keytabs, tgts, azvms
}

// CollectArtifactsOpenGraph collects all
func (l LinhoundCollector) CollectArtifactsOpenGraph(duration int) string {
	var nodes []*openGraphNode
	var edges []*openGraphEdge

	// collect raw artifacts from the system
	sudoers, privKeys, fwdKeys, authKeys, keytabs, tgts, azvms := l.CollectArtifacts(duration)

	// convert LinhoundObjects to OpenGraph nodes and edges
	for _, element := range sudoers {
		nodesTmp, edgesTmp := LinhoundToOpenGraphObjects(*element)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}
	for _, element := range privKeys {
		nodesTmp, edgesTmp := LinhoundToOpenGraphObjects(*element)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}
	for _, element := range fwdKeys {
		nodesTmp, edgesTmp := LinhoundToOpenGraphObjects(*element)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}
	for _, element := range authKeys {
		nodesTmp, edgesTmp := LinhoundToOpenGraphObjects(*element)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}
	for _, element := range keytabs {
		edgeTmp := KeyTabToOpenGraph(*element)
		edges = append(edges, edgeTmp...)
	}
	for _, element := range tgts {
		edgeTmp := TGTToOpenGraph(*element)
		edges = append(edges, edgeTmp...)
	}
	for _, element := range azvms {
		nodesTmp, edgesTmp := AZVMToOpenGraph(*element)
		nodes = append(nodes, nodesTmp...)
		edges = append(edges, edgesTmp...)
	}

	// convert to OpenGraph structure
	var og openGraph
	// don't set source_kind because it leads to ingest problems
	// og.Metadata.SourceKind = "GolinHound"
	og.Graph.Nodes = unique(nodes)
	og.Graph.Edges = unique(edges)
	jsonBytes, _ := json.Marshal(og)

	return string(jsonBytes)
}

// unqiue takes a slice of object pointers and deduplicates the dereferenced objects
func unique[T any](elements []*T) []*T {
	seen := make(map[string]struct{})
	var result []*T

	for _, element := range elements {
		jsonBytes, _ := json.Marshal(element)
		key := string(jsonBytes)

		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			result = append(result, element)
		}
	}

	return result
}

// Verbose defines whether verbose logging is enabled
var Verbose = false

// logVerbose only prints the specified string if verbose logging is enabled
func logVerbose(format string, args ...any) {
	if Verbose {
		log.Printf("[DEBUG] "+format, args...)
	}
}
