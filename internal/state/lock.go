package state

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

const staleLockAge = 10 * time.Second

// FileLock represents an exclusive file lock using lock file creation
// This implementation doesn't use syscall.Flock which is not available in Traefik plugins
type FileLock struct {
	lockPath string
	pid      int
	owner    string
}

type lockPIDFile interface {
	io.StringWriter
	io.Closer
	Sync() error
}

var (
	lockOwnerMu      sync.Mutex
	lockOwnerCounter uint64
)

// NewFileLock creates a new file lock for the given path.
// It uses a separate .lock file to coordinate access.
func NewFileLock(path string) (*FileLock, error) {
	pid := os.Getpid()
	return &FileLock{
		lockPath: path,
		pid:      pid,
		owner:    newLockOwner(pid),
	}, nil
}

func newLockOwner(pid int) string {
	lockOwnerMu.Lock()
	defer lockOwnerMu.Unlock()
	lockOwnerCounter++
	return fmt.Sprintf("%d:%d", pid, lockOwnerCounter)
}

// Lock acquires an exclusive lock by creating a lock file.
// It will retry for up to 5 seconds if the lock is held by another process.
func (fl *FileLock) Lock() error {
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		// Try to create lock file exclusively
		f, err := os.OpenFile(fl.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			// Successfully created lock file
			if err := writeLockPID(f, fl.lockPath, fl.owner); err != nil {
				return err
			}
			// We hold the lock
			return nil
		}

		removedStale, staleErr := fl.removeStaleLock()
		if staleErr != nil {
			return staleErr
		}
		if removedStale {
			continue
		}

		// If stat failed (e.g., file removed between OpenFile and Stat)
		// or lock is not stale, wait for next tick
		select {
		case <-timeout.C:
			return fmt.Errorf("timeout waiting for file lock")
		case <-ticker.C:
			// Continue to next iteration
		}
	}
}

func (fl *FileLock) removeStaleLock() (bool, error) {
	info, statErr := os.Stat(fl.lockPath)
	if statErr != nil {
		return false, nil
	}
	if time.Since(info.ModTime()) <= staleLockAge {
		return false, nil
	}

	cleanupPath := fl.lockPath + ".cleanup"
	cleanupFile, err := os.OpenFile(cleanupPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- lock path derives from trusted persistent state configuration.
	if err != nil {
		return false, nil
	}
	if err := writeLockPID(cleanupFile, cleanupPath, fl.owner); err != nil {
		return false, fmt.Errorf("failed to create stale lock cleanup guard: %w", err)
	}
	defer os.Remove(cleanupPath) //nolint:errcheck

	info, statErr = os.Stat(fl.lockPath)
	if statErr != nil {
		return os.IsNotExist(statErr), nil
	}
	if time.Since(info.ModTime()) <= staleLockAge {
		return false, nil
	}

	if err := os.Remove(fl.lockPath); err != nil && !os.IsNotExist(err) {
		return false, fmt.Errorf("unable to remove stale lock: %v", err)
	}
	return true, nil
}

func writeLockPID(file lockPIDFile, lockPath string, owner string) (err error) {
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("failed to close lock file: %w", closeErr)
		}
		if err != nil {
			_ = os.Remove(lockPath)
		}
	}()

	if _, err := file.WriteString(owner); err != nil {
		return fmt.Errorf("failed to write pid to lock file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync lock file: %w", err)
	}
	return nil
}

// Unlock releases the exclusive lock by removing the lock file
// This is now safer and checks the PID.
func (fl *FileLock) Unlock() error {
	content, err := os.ReadFile(fl.lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already unlocked
		}
		return fmt.Errorf("failed to read lock file on unlock: %v", err)
	}

	lockPIDStr := string(content)
	myOwner := fl.owner

	if lockPIDStr != myOwner {
		// This is not our lock. Do not remove it.
		return fmt.Errorf("cannot unlock file held by different process (my_pid: %d, my_owner: %s, lock_owner: %s)", fl.pid, myOwner, lockPIDStr)
	}

	// It is our lock, remove it.
	err = os.Remove(fl.lockPath)
	if err != nil && !os.IsNotExist(err) {
		// Failed to remove, and not because it was already gone
		return fmt.Errorf("failed to remove our lock file: %v", err)
	}

	// Succeeded, or it was already gone (which is fine)
	return nil
}

// Close is an alias for Unlock for compatibility.
// It will not return an error if the lock is held by another process.
func (fl *FileLock) Close() error {
	err := fl.Unlock()

	// If Unlock fails, we only want to suppress the error
	// if it's because the lock is held by someone else.
	// In the context of Close(), this is fine.
	if err != nil {
		if strings.Contains(err.Error(), "cannot unlock file held by different process") {
			return nil
		}
		// IsNotExist is already handled by Unlock, but this is safe.
		if os.IsNotExist(err) {
			return nil
		}
	}

	return err
}
