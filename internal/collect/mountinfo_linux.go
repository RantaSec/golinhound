package collect

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
)

const (
	procMountInfoPath = "/proc/self/mountinfo"
	maxSymlinkHops    = 40
)

type mountEntry struct {
	mountPoint string
	fsType     string
}

type fsGuard struct {
	includeRemoteFS bool
	mounts          []mountEntry
	mountsErr       error
}

var activeFSGuard atomic.Pointer[fsGuard]

// localFSTypes lists non-remote Linux filesystems safe to access without
// risking network or userspace-daemon hangs. Network, clustered, FUSE,
// and autofs filesystems are intentionally omitted.
var localFSTypes = map[string]bool{
	// Linux disk/flash filesystems
	"ext2":     true,
	"ext3":     true,
	"ext4":     true,
	"xfs":      true,
	"btrfs":    true,
	"zfs":      true,
	"bcachefs": true,
	"f2fs":     true,
	"jfs":      true,
	"reiserfs": true,
	"nilfs2":   true,
	"minix":    true,
	"ufs":      true,

	// Local cross-OS / removable media filesystems (in-kernel)
	"vfat":    true,
	"msdos":   true,
	"fat":     true,
	"exfat":   true,
	"ntfs":    true,
	"ntfs3":   true,
	"hfs":     true,
	"hfsplus": true,

	// Layered, encrypted, and read-only image filesystems
	"overlay":   true,
	"overlayfs": true,
	"aufs":      true,
	"ecryptfs":  true,
	"squashfs":  true,
	"erofs":     true,
	"cramfs":    true,
	"romfs":     true,
	"iso9660":   true,
	"udf":       true,

	// Memory and kernel virtual/pseudo filesystems
	"tmpfs":       true,
	"devtmpfs":    true,
	"ramfs":       true,
	"rootfs":      true,
	"proc":        true,
	"sysfs":       true,
	"devpts":      true,
	"cgroup":      true,
	"cgroup2":     true,
	"securityfs":  true,
	"selinuxfs":   true,
	"efivarfs":    true,
	"pstore":      true,
	"mqueue":      true,
	"hugetlbfs":   true,
	"debugfs":     true,
	"tracefs":     true,
	"configfs":    true,
	"binfmt_misc": true,

	// VM host-guest shared filesystems
	"virtiofs": true,
	"9p":       true,
	"vboxsf":   true,
}

func newProcFSGuard() *fsGuard {
	mounts, err := readProcMountInfo()
	return &fsGuard{
		mounts:    mounts,
		mountsErr: err,
	}
}

// configureFSGuard initializes the package-wide filesystem guard for Run.
func configureFSGuard(includeRemoteFS bool) {
	if includeRemoteFS {
		activeFSGuard.Store(&fsGuard{includeRemoteFS: true})
		return
	}
	activeFSGuard.Store(newProcFSGuard())
}

func currentFSGuard() *fsGuard {
	if g := activeFSGuard.Load(); g != nil {
		return g
	}
	g := newProcFSGuard()
	if activeFSGuard.CompareAndSwap(nil, g) {
		return g
	}
	return activeFSGuard.Load()
}

func readProcMountInfo() ([]mountEntry, error) {
	data, err := os.ReadFile(procMountInfoPath)
	if err != nil {
		return nil, err
	}
	return parseMountInfo(string(data)), nil
}

// parseMountInfo parses Linux /proc/self/mountinfo lines into mountEntry records.
func parseMountInfo(data string) []mountEntry {
	var mounts []mountEntry
	for line := range strings.SplitSeq(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "<id> <parent> <maj:min> <root> <mountpoint> <opts> [optional...] - <fstype> <source> <superopts>"
		before, after, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		bf := strings.Fields(before)
		af := strings.Fields(after)
		if len(bf) < 6 || len(af) < 1 {
			continue
		}
		mp := filepath.Clean(unescapeMountPath(bf[4]))
		if !filepath.IsAbs(mp) {
			continue
		}
		mounts = append(mounts, mountEntry{
			mountPoint: mp,
			fsType:     af[0],
		})
	}
	return mounts
}

// unescapeMountPath decodes octal escapes (\040, \011, \012, \134, ...) emitted
// by Linux seq_path in /proc/self/mountinfo.
func unescapeMountPath(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+3 < len(s) &&
			s[i+1] >= '0' && s[i+1] <= '3' &&
			s[i+2] >= '0' && s[i+2] <= '7' &&
			s[i+3] >= '0' && s[i+3] <= '7' {
			val := (s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3]-'0')
			b.WriteByte(val)
			i += 4
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// isMountLocal resolves p lexically against mounts using longest-prefix match.
// On equal-length ties (stacked overmounts), later entries win.
func isMountLocal(p string, mounts []mountEntry) (local bool, mountPoint, fsType string) {
	var matched *mountEntry
	bestLen := -1
	for i := range mounts {
		mp := mounts[i].mountPoint
		if mp == "/" || p == mp || strings.HasPrefix(p, mp+"/") {
			if len(mp) >= bestLen {
				bestLen = len(mp)
				matched = &mounts[i]
			}
		}
	}
	if matched == nil {
		return false, "/", "unknown"
	}
	return localFSTypes[matched.fsType], matched.mountPoint, matched.fsType
}

// checkPathOnLocalFS verifies that p (and any local symlinks along p) resolves
// solely through filesystems in localFSTypes. Non-local paths and mountpoints
// are rejected via mountinfo before os.Lstat is ever called on them.
func checkPathOnLocalFS(p string, mounts []mountEntry) (local bool, mountPoint, fsType string) {
	cleaned := filepath.Clean(p)
	if !filepath.IsAbs(cleaned) {
		return false, "", "relative path"
	}

hops:
	for range maxSymlinkHops + 1 {
		if ok, mp, ft := isMountLocal(cleaned, mounts); !ok {
			return false, mp, ft
		}
		if cleaned == "/" {
			return true, "", ""
		}

		parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
		cur := ""
		for i, part := range parts {
			cur += "/" + part
			if ok, mp, ft := isMountLocal(cur, mounts); !ok {
				return false, mp, ft
			}
			fi, err := os.Lstat(cur)
			if err != nil {
				// cur is already verified local in mounts; missing/inaccessible
				// paths are handled by the caller without triggering remote warnings.
				return true, "", ""
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(cur)
				if err != nil {
					if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.EINVAL) {
						return true, "", ""
					}
					return false, cur, "unreadable symlink"
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(cur), target)
				}
				cleaned = filepath.Join(target, filepath.Join(parts[i+1:]...))
				continue hops
			}
		}
		return true, "", ""
	}
	return false, cleaned, "too many symlinks"
}

// isPathOnLocalFS reports whether p sits on a local filesystem in localFSTypes
// (or whether -include-remote-fs is enabled). Non-local paths are skipped with
// a warning without touching the underlying mount.
func isPathOnLocalFS(p string) bool {
	g := currentFSGuard()
	if g.includeRemoteFS {
		return true
	}
	if g.mountsErr != nil {
		slog.Warn("could not read /proc/self/mountinfo, skipping path", "path", p, "err", g.mountsErr)
		return false
	}
	ok, mp, fsType := checkPathOnLocalFS(p, g.mounts)
	if !ok {
		slog.Warn("skipping path on non-local filesystem", "path", p, "mountPoint", mp, "fsType", fsType)
	}
	return ok
}
