package collect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// User is one local account.
type User struct {
	UserName string
	UID      string
	Shell    string
	HomeDir  string
}

// Host is a per-run snapshot of the machine state. referencedUsers
// is the set of UIDs some collector has referenced during the run.
type Host struct {
	uniqueId        string
	FQDN            string
	Users           map[string]*User
	referencedUsers map[string]struct{}
}

// NewHost captures a per-run snapshot of the machine: HMAC'd
// machine-id, FQDN, and the enumerated user set. Root is required
// so /etc/passwd and journalctl reads never fail on permissions.
func NewHost() (*Host, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("this program must run as root")
	}

	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, fmt.Errorf("/etc/machine-id: %w", err)
	}
	machineId := strings.TrimSuffix(string(raw), "\n")
	if len(machineId) != 32 {
		return nil, fmt.Errorf("/etc/machine-id: expected 32 bytes, got %d", len(machineId))
	}
	h := hmac.New(sha256.New, []byte("fLhn74XaBtmouSQkBSRIAm6tbISvrf26"))
	h.Write([]byte(machineId))
	uniqueId := strings.TrimRight(base64.StdEncoding.EncodeToString(h.Sum(nil)), "=")

	fqdn, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("hostname: %w", err)
	}

	users, err := enumerateUsers()
	if err != nil {
		return nil, err
	}

	return &Host{
		uniqueId:        uniqueId,
		FQDN:            fqdn,
		Users:           users,
		referencedUsers: make(map[string]struct{}),
	}, nil
}

// ComputerID returns the HMAC'd machine-id used as the stable
// per-host identifier in the graph.
func (h *Host) ComputerID() string { return h.uniqueId }

// ReferenceUser marks uid for emission and returns its SSHUser id.
// Every caller should be inline in an AddEdge argument list. The
// mark drives OSCollector.Finalize's per-user emission.
func (h *Host) ReferenceUser(uid string) string {
	h.referencedUsers[uid] = struct{}{}
	return uid + "@" + h.uniqueId
}

// enumerateUsers reads /etc/passwd into a UID-keyed map.
func enumerateUsers() (map[string]*User, error) {
	slog.Debug("enumerateUsers")
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("/etc/passwd: %w", err)
	}
	users := make(map[string]*User)
	for line := range strings.SplitSeq(string(data), "\n") {
		if u, ok := parsePasswdLine(line); ok {
			users[u.UID] = u
		}
	}
	return users, nil
}

// parsePasswdLine parses one passwd line into a *User.
func parsePasswdLine(line string) (*User, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, false
	}
	fields := strings.Split(line, ":")
	if len(fields) != 7 {
		return nil, false
	}
	return &User{
		UserName: fields[0],
		UID:      fields[2],
		HomeDir:  fields[5],
		Shell:    fields[6],
	}, true
}
