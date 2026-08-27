package application

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const maxUnixSocketPath = 107

// runtimeDir owns one invocation's private runtime directory.
type runtimeDir struct {
	Directory  string
	HTTPSocket string
	SOCKSocket string
}

func createRuntimeDir(uid int, runtimeDirectory string) (*runtimeDir, error) {
	base := runtimeDirectory
	if base == "" {
		base = filepath.Join("/tmp", fmt.Sprintf("airjail-%d", uid))
	} else {
		base = filepath.Join(base, "airjail")
	}

	err := ensurePrivateDirectory(base, uid)
	if err != nil {
		return nil, err
	}

	directory, err := os.MkdirTemp(base, "session-")
	if err != nil {
		return nil, fmt.Errorf("create session directory in %q: %w", base, err)
	}

	err = os.Chmod(directory, 0o700)
	if err != nil {
		_ = os.RemoveAll(directory)

		return nil, fmt.Errorf("set session directory permissions: %w", err)
	}

	runDir := &runtimeDir{
		Directory:  directory,
		HTTPSocket: filepath.Join(directory, "http.sock"),
		SOCKSocket: filepath.Join(directory, "socks.sock"),
	}
	if len(runDir.HTTPSocket) > maxUnixSocketPath || len(runDir.SOCKSocket) > maxUnixSocketPath {
		_ = os.RemoveAll(directory)

		return nil, fmt.Errorf("session socket path exceeds Linux Unix socket path limit under %q", base)
	}

	return runDir, nil
}

// Close removes this invocation's runtime directory.
func (sess *runtimeDir) Close() error {
	err := os.RemoveAll(sess.Directory)
	if err != nil {
		return fmt.Errorf("remove session directory %q: %w", sess.Directory, err)
	}

	return nil
}

func ensurePrivateDirectory(path string, uid int) error {
	err := os.Mkdir(path, 0o700)
	if err == nil {
		return nil
	}

	if !os.IsExist(err) {
		return fmt.Errorf("create runtime directory %q: %w", path, err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect runtime directory %q: %w", path, err)
	}

	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runtime path %q is not a real directory", path)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect runtime directory %q ownership: unavailable", path)
	}

	if int(stat.Uid) != uid {
		return fmt.Errorf("runtime directory %q is owned by UID %d, want %d", path, stat.Uid, uid)
	}

	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("runtime directory %q permissions %04o are not private", path, info.Mode().Perm())
	}

	return nil
}
