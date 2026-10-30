package namespace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const descendantTestStage = "AIRJAIL_DESCENDANT_TEST_STAGE"

func TestRunTerminatesDetachedDescendants(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"process-group", "session"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()

			pidPath := filepath.Join(t.TempDir(), "pid")
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDescendantCleanupProcess$")

			command.Env = append(os.Environ(),
				descendantTestStage+"=supervisor",
				"AIRJAIL_DESCENDANT_TEST_MODE="+mode,
				"AIRJAIL_DESCENDANT_TEST_PID="+pidPath,
			)

			defer func() {
				// Avoid leaving a long-running process behind if the regression returns.
				pid, err := readDescendantTestPID(pidPath)
				if err == nil {
					_ = unix.Kill(pid, unix.SIGKILL)
				}
			}()

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("cleanup subprocess: %v\n%s", err, output)
			}
		})
	}
}

func TestDescendantCleanupProcess(t *testing.T) {
	switch os.Getenv(descendantTestStage) {
	case "":
		return
	case "supervisor":
		err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
		if err != nil {
			t.Fatalf("set subreaper: %v", err)
		}

		environment := append(os.Environ(), descendantTestStage+"=parent")

		exitCode, err := runSandboxedProcess(t.Context(),
			[]string{os.Args[0], "-test.run=^TestDescendantCleanupProcess$"},
			runOptions{Environment: environment, ReapDescendants: true},
		)
		if err != nil || exitCode != 42 {
			t.Fatalf("runSandboxedProcess = %d, %v, want 42, nil", exitCode, err)
		}

		pid, err := readDescendantTestPID(os.Getenv("AIRJAIL_DESCENDANT_TEST_PID"))
		if err != nil {
			t.Fatal(err)
		}

		err = unix.Kill(pid, 0)
		if !errors.Is(err, unix.ESRCH) {
			t.Fatalf("descendant %d remains alive or unreaped: %v", pid, err)
		}
	case "parent":
		command := exec.Command("sleep", "900") //nolint:noctx // Must outlive this parent to exercise orphan cleanup.

		command.SysProcAttr = &syscall.SysProcAttr{}
		if os.Getenv("AIRJAIL_DESCENDANT_TEST_MODE") == "session" {
			command.SysProcAttr.Setsid = true
		} else {
			command.SysProcAttr.Setpgid = true
		}

		err := command.Start()
		if err != nil {
			t.Fatalf("start detached descendant: %v", err)
		}

		err = os.WriteFile(os.Getenv("AIRJAIL_DESCENDANT_TEST_PID"),
			[]byte(strconv.Itoa(command.Process.Pid)), 0o600)
		if err != nil {
			_ = command.Process.Kill()

			t.Fatalf("write descendant PID: %v", err)
		}

		os.Exit(42)
	default:
		t.Fatal("unexpected descendant test stage")
	}
}

func readDescendantTestPID(path string) (int, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read descendant PID: %w", err)
	}

	pid, err := strconv.Atoi(string(contents))
	if err != nil {
		return 0, fmt.Errorf("parse descendant PID: %w", err)
	}

	return pid, nil
}
