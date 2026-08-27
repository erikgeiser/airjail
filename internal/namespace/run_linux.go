package namespace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sys/unix"
)

type runOptions struct {
	Environment            []string
	Directory              string
	Sys                    *syscall.SysProcAttr
	JoinParentProcessGroup bool
	ReapProcessGroup       bool
	Logger                 *logging.Logger
}

func runSandboxedProcess(ctx context.Context, command []string, options runOptions) (int, error) {
	if len(command) == 0 {
		return 0, fmt.Errorf("run process: command is empty")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return 0, fmt.Errorf("look up command %q: %w", command[0], err)
	}

	terminal, originalForeground := terminalForeground()
	manageForeground := shouldManageForeground(
		terminal,
		options.JoinParentProcessGroup,
		originalForeground,
		unix.Getpgrp(),
	)

	sys := cloneSysProcAttr(options.Sys)
	if !options.JoinParentProcessGroup {
		sys.Setpgid = true
	}

	if manageForeground {
		signal.Ignore(syscall.SIGTTOU)

		sys.Foreground = true
		sys.Ctty = int(os.Stdin.Fd())
	}

	child := &exec.Cmd{
		Path:        path,
		Args:        command,
		Env:         options.Environment,
		Dir:         options.Directory,
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		SysProcAttr: sys,
	}

	options.Logger.Debugf("start sandboxed process: %s", strings.Join(command, " "))

	err = child.Start()
	if err != nil {
		return 0, fmt.Errorf("start command %q: %w", command[0], err)
	}

	pid := child.Process.Pid
	childFinished := false

	signalTarget := -pid
	if options.JoinParentProcessGroup {
		signalTarget = pid
	}

	done := make(chan struct{})
	forwarderStopped := make(chan struct{})
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, forwardedSignals()...)

	go func() {
		defer close(forwarderStopped)

		forwardSignals(ctx, signals, done, signalTarget, options.Logger)
	}()

	defer func() {
		signal.Stop(signals)
		close(done)
		<-forwarderStopped
	}()

	defer func() {
		if !childFinished {
			logIgnoredError(options.Logger, "kill process during cleanup", unix.Kill(signalTarget, unix.SIGKILL))
		}

		if manageForeground {
			logIgnoredError(
				options.Logger,
				"restore terminal foreground process group during cleanup",
				setTerminalForeground(originalForeground),
			)
		}

		logIgnoredError(options.Logger, "release process during cleanup", child.Process.Release())
	}()

	// wait for the child process, but actually all states and not just full
	// exit like child.Wait() would, so it needs to be handled manually.
	for {
		var status unix.WaitStatus

		_, err = unix.Wait4(pid, &status, unix.WUNTRACED|unix.WCONTINUED, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}

		if err != nil {
			return 0, fmt.Errorf("wait for command %q: %w", command[0], err)
		}

		switch {
		case status.Exited():
			childFinished = true

			if options.ReapProcessGroup {
				reapErr := terminateAndReapProcessGroup(pid)
				if reapErr != nil {
					return 0, reapErr
				}
			}

			return status.ExitStatus(), nil
		case status.Signaled():
			childFinished = true

			if options.ReapProcessGroup {
				reapErr := terminateAndReapProcessGroup(pid)
				if reapErr != nil {
					return 0, reapErr
				}
			}

			return 128 + int(status.Signal()), nil
		case status.Stopped():
			// When the child stops, airjail stops itselfs so that the caller
			// (e.g. the shell) can treat airjail like it would treat the child
			// process if airjail was not in the middle. If airjail is resumed,
			// it then returns the child again.
			if manageForeground {
				logIgnoredError(
					options.Logger,
					"restore terminal foreground process group for stopped process",
					setTerminalForeground(originalForeground),
				)
			}

			err = unix.Kill(os.Getpid(), unix.SIGSTOP)
			if err != nil {
				return 0, fmt.Errorf("stop supervisor: %w", err)
			}

			if manageForeground {
				logIgnoredError(
					options.Logger,
					"restore child terminal foreground process group after resume",
					setTerminalForeground(pid),
				)
			}

			logIgnoredError(options.Logger, "continue child process after resume", unix.Kill(signalTarget, unix.SIGCONT))
		}
	}
}

func terminateAndReapProcessGroup(processGroup int) error {
	killErr := unix.Kill(-processGroup, unix.SIGKILL)
	if killErr != nil && !errors.Is(killErr, unix.ESRCH) {
		return fmt.Errorf("kill rem aining processes in group %d: %w", processGroup, killErr)
	}

	for {
		var status unix.WaitStatus

		_, err := unix.Wait4(-processGroup, &status, 0, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}

		if errors.Is(err, unix.ECHILD) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("reap remaining processes in group %d: %w", processGroup, err)
		}
	}
}

func cloneSysProcAttr(source *syscall.SysProcAttr) *syscall.SysProcAttr {
	if source == nil {
		return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	}

	cloned := *source
	if cloned.Pdeathsig == 0 {
		cloned.Pdeathsig = syscall.SIGKILL
	}

	return &cloned
}

func terminalForeground() (bool, int) {
	_, err := os.Stdin.Stat()
	if err != nil {
		return false, 0
	}

	foreground, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return false, 0
	}

	return true, foreground
}

func shouldManageForeground(
	terminal bool,
	joinParentProcessGroup bool,
	foregroundProcessGroup int,
	currentProcessGroup int,
) bool {
	return terminal && !joinParentProcessGroup && foregroundProcessGroup == currentProcessGroup
}

func setTerminalForeground(processGroup int) error {
	return unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, processGroup)
}

func forwardSignals(
	ctx context.Context,
	signals <-chan os.Signal,
	done <-chan struct{},
	signalTarget int,
	logger *logging.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			logIgnoredError(logger, "terminate process after cancellation", unix.Kill(signalTarget, unix.SIGTERM))

			timer := time.NewTimer(3 * time.Second)
			select {
			case <-timer.C:
				logIgnoredError(logger, "kill process after cancellation timeout", unix.Kill(signalTarget, unix.SIGKILL))
			case <-done:
				if !timer.Stop() {
					<-timer.C
				}
			}

			return
		case received := <-signals:
			signalValue, ok := received.(syscall.Signal)
			if ok {
				logIgnoredError(logger, fmt.Sprintf("forward signal %s", signalValue), unix.Kill(signalTarget, signalValue))
			}
		case <-done:
			return
		}
	}
}

func logIgnoredError(logger *logging.Logger, operation string, err error) {
	if err == nil {
		return
	}

	logger.Debugf("ignored error while attempting to %s: %v", operation, err)
}

func forwardedSignals() []os.Signal {
	return []os.Signal{
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGTSTP,
		syscall.SIGWINCH,
	}
}
