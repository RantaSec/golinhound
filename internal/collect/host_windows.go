package collect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// User is one local account. UID is the SID string; Shell is unused
// on Windows.
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
// machine GUID, FQDN, and the enumerated user set.
func NewHost() (*Host, error) {
	guid, err := readMachineGUID()
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, []byte("fLhn74XaBtmouSQkBSRIAm6tbISvrf26"))
	h.Write([]byte(guid))
	uniqueId := strings.TrimRight(base64.StdEncoding.EncodeToString(h.Sum(nil)), "=")

	fqdn, err := computerFQDN()
	if err != nil {
		return nil, fmt.Errorf("computer FQDN: %w", err)
	}

	netbios, err := netbiosName()
	if err != nil {
		return nil, fmt.Errorf("NetBIOS computer name: %w", err)
	}

	users, err := enumerateUserProfiles(netbios)
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

// readMachineGUID reads the MachineGuid - Windows' per-install
// identifier, stable across reboots and reset only by reinstall.
func readMachineGUID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", fmt.Errorf("open HKLM\\SOFTWARE\\Microsoft\\Cryptography: %w", err)
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", fmt.Errorf("read MachineGuid: %w", err)
	}
	if guid == "" {
		return "", errors.New("MachineGuid is empty")
	}
	return guid, nil
}

// computerFQDN returns the machine's fully-qualified DNS name (or
// the short hostname on a non-domain-joined host).
func computerFQDN() (string, error) {
	// DNS_MAX_NAME_BUFFER_LENGTH.
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(windows.ComputerNamePhysicalDnsFullyQualified, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// netbiosName returns the machine's short NetBIOS/SAM name — the
// same string LookupAccountSid uses as the domain for local
// principals. Used to detect (and strip) the "MACHINE\" prefix from
// local user names so a workgroup host stores plain `Administrator`
// instead of `WIN2022\Administrator`.
func netbiosName() (string, error) {
	// MAX_COMPUTERNAME_LENGTH+1 covers every NetBIOS name.
	n := uint32(16)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(windows.ComputerNameNetBIOS, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// enumerateUserProfiles walks ProfileList.
func enumerateUserProfiles(netbios string) (map[string]*User, error) {
	slog.Debug("enumerateUserProfiles")
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open HKLM ProfileList: %w", err)
	}
	defer root.Close()

	sids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate ProfileList: %w", err)
	}

	users := make(map[string]*User)
	for _, sidStr := range sids {
		if !strings.HasPrefix(sidStr, "S-1-5-21-") {
			continue
		}
		// ProfileImagePath is REG_EXPAND_SZ (e.g. %SystemDrive%\Users\Alice).
		sub, err := registry.OpenKey(root, sidStr, registry.QUERY_VALUE|registry.WOW64_64KEY)
		if err != nil {
			slog.Error("enumerateUserProfiles: ProfileList sub-key unreadable", "sid", sidStr, "err", err)
			continue
		}
		rawHomeDir, _, err := sub.GetStringValue("ProfileImagePath")
		sub.Close()
		if err != nil {
			slog.Error("enumerateUserProfiles: ProfileImagePath unreadable", "sid", sidStr, "err", err)
			continue
		}
		homeDir, err := registry.ExpandString(rawHomeDir)
		if err != nil {
			slog.Error("enumerateUserProfiles: ProfileImagePath expansion failed", "sid", sidStr, "err", err)
			continue
		}

		sid, err := windows.StringToSid(sidStr)
		if err != nil {
			slog.Error("enumerateUserProfiles: SID could not be parsed", "sid", sidStr, "err", err)
			continue
		}
		name, domain, _, err := sid.LookupAccount("")
		if err != nil {
			slog.Error("enumerateUserProfiles: SID cannot be resolved to a name", "sid", sidStr, "err", err)
			continue
		}
		if domain != "" && !strings.EqualFold(domain, netbios) {
			// Real AD domain: keep the prefix so `alice` and
			// `CORP\alice` remain distinguishable in the graph.
			// local machine SAM domain: drop it so
			// a workgroup Administrator is displayed as
			// `Administrator` rather than `WIN2022\Administrator`.
			name = domain + `\` + name
		}
		users[sidStr] = &User{
			UserName: name,
			UID:      sidStr,
			HomeDir:  homeDir,
		}
	}
	return users, nil
}

func (h *Host) ComputerID() string { return h.uniqueId }

// ReferenceUser marks uid for emission and returns its SSHUser id.
// Every caller should be inline in an AddEdge argument list. The
// mark drives OSCollector.Finalize's per-user emission.
func (h *Host) ReferenceUser(uid string) string {
	h.referencedUsers[uid] = struct{}{}
	return uid + "@" + h.uniqueId
}
