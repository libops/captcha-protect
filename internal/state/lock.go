package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// FileLock represents an exclusive file lock using lock file creation
// This implementation doesn't use syscall.Flock which is not available in Traefik plugins
type FileLock struct {
	lockPath string
	pid      int
}

// NewFileLock creates a new file lock for the given path.
// It uses a separate .lock file to coordinate access.
func NewFileLock(path string) (*FileLock, error) {
	return &FileLock{
		lockPath: path,
		pid:      os.Getpid(),
	}, nil
}

// Lock acquires an exclusive lock by creating a lock file.
// It will retry for up to 5 seconds if the lock is held by another process.
func (fl *FileLock) Lock() error {
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		// Try to create lock file exclusively
		f, err := os.OpenFile(fl.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			// Successfully created lock file
			_, err = f.WriteString(strconv.Itoa(fl.pid))
			f.Close()
			// Check for write error
			if err != nil {
				// We got the lock but failed to write.
				// Best effort to clean up, then return the error.
				_ = os.Remove(fl.lockPath)
				return fmt.Errorf("failed to write pid to lock file: %v", err)
			}
			// We hold the lock
			return nil
		}

		// If we're here, os.OpenFile failed, likely because the file exists.
		// Check if lock file is stale (older than 10 seconds)
		info, statErr := os.Stat(fl.lockPath)
		if statErr == nil {
			if time.Since(info.ModTime()) > 10*time.Second {
				// Lock file is stale, try to remove it
				removeErr := os.Remove(fl.lockPath)

				if removeErr != nil && !os.IsNotExist(removeErr) {
					// If we can't remove it (and it's not 'not exist'),
					// something is wrong (e.g., permissions).
					return fmt.Errorf("unable to remove stale lock: %v", removeErr)
				}
				// Successfully removed stale lock, retry immediately
				// This reduces the race window significantly
				continue
			}
		}

		// If stat failed (e.g., file removed between OpenFile and Stat)
		// or lock is not stale, wait for next tick
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for file lock")
		case <-ticker.C:
			// Continue to next iteration
		}
	}
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
	myPIDStr := strconv.Itoa(fl.pid)

	if lockPIDStr != myPIDStr {
		// This is not our lock. Do not remove it.
		return fmt.Errorf("cannot unlock file held by different process (my_pid: %s, lock_pid: %s)", myPIDStr, lockPIDStr)
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
