package worker

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Bubblewrap struct {
	Root        string
	Broker      string
	TmpBytes    string
	MemoryLimit string
	MaxProcs    string
	Args        []string
}

// Command runs this executable with Args over the read-only Root, where it reaches its broker at the path Broker.
func (b Bubblewrap) Command(broker string) (*exec.Cmd, error) {
	root, err := filepath.Abs(b.Root)
	if err != nil || b.Root == "" || root == "/" {
		return nil, errors.New("worker root must be a prepared filesystem directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || root == "/" {
		return nil, errors.New("worker root must be a prepared filesystem directory")
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, errors.New("worker root directory does not exist")
	}
	executable, err := os.Executable()
	if err == nil {
		executable, err = filepath.Abs(executable)
	}
	if err != nil {
		return nil, err
	}
	launcher, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, errors.New("bubblewrap is required for connector workers")
	}
	userns := "--disable-userns"
	if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(value)) == "0" {
		userns = "--assert-userns-disabled"
	}
	cmd := exec.Command(launcher, append([]string{"--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", userns, "--cap-drop", "ALL", "--clearenv",
		"--ro-bind", root, "/", "--ro-bind", executable, "/worker",
		"--ro-bind", broker, b.Broker, "--proc", "/proc", "--dev", "/dev",
		"--size", b.TmpBytes, "--tmpfs", "/tmp", "--chdir", "/tmp",
		"--remount-ro", "/dev", "--remount-ro", "/",
		"--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--setenv", "GOMEMLIMIT", b.MemoryLimit, "--setenv", "GOMAXPROCS", b.MaxProcs, "--", "/worker"}, b.Args...)...)
	cmd.Env = []string{}
	return cmd, nil
}
