package namespace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type runOptions struct {
	Environment            []string
	Directory              string
	Sys                    *syscall.SysProcAttr
	JoinParentProcessGroup bool
	ReapProcessGroup       bool
}

func runSupervisor(ctx context.Context, command []string, options runOptions) (int, error) {
	if len(command) == 0 {
		return 0, fmt.Errorf("run process: command is empty")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return 0, fmt.Errorf("look up command %q: %w", command[0], err)
	}

	terminal, originalForeground := terminalForeground()

	sys := cloneSysProcAttr(options.Sys)
	if !options.JoinParentProcessGroup {
		sys.Setpgid = true
	}

	if terminal && !options.JoinParentProcessGroup {
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

		forwardSignals(ctx, signals, done, signalTarget)
	}()

	defer func() {
		signal.Stop(signals)
		close(done)
		<-forwarderStopped
	}()

	defer func() {
		if !childFinished {
			_ = unix.Kill(signalTarget, unix.SIGKILL)
		}

		if terminal {
			_ = setTerminalForeground(originalForeground)
		}

		_ = child.Process.Release()
	}()

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
			if terminal {
				_ = setTerminalForeground(originalForeground)
			}

			err = unix.Kill(os.Getpid(), unix.SIGSTOP)
			if err != nil {
				return 0, fmt.Errorf("stop supervisor: %w", err)
			}

			if terminal && !options.JoinParentProcessGroup {
				_ = setTerminalForeground(pid)
			}

			_ = unix.Kill(signalTarget, unix.SIGCONT)
		}
	}
}

func terminateAndReapProcessGroup(processGroup int) error {
	killErr := unix.Kill(-processGroup, unix.SIGKILL)
	if killErr != nil && !errors.Is(killErr, unix.ESRCH) {
		return fmt.Errorf("kill remaining processes in group %d: %w", processGroup, killErr)
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

func setTerminalForeground(processGroup int) error {
	return unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCSPGRP, processGroup)
}

func forwardSignals(ctx context.Context, signals <-chan os.Signal, done <-chan struct{}, signalTarget int) {
	for {
		select {
		case <-ctx.Done():
			_ = unix.Kill(signalTarget, unix.SIGTERM)

			select {
			case <-time.After(3 * time.Second):
				_ = unix.Kill(signalTarget, unix.SIGKILL)
			case <-done:
			}

			return
		case received := <-signals:
			signalValue, ok := received.(syscall.Signal)
			if ok {
				_ = unix.Kill(signalTarget, signalValue)
			}
		case <-done:
			return
		}
	}
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
