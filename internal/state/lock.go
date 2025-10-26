package state

import (
	"fmt"
	"os"
	"strconv"
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
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for file lock")
		case <-ticker.C:
			// Try to create lock file exclusively
			f, err := os.OpenFile(fl.lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err == nil {
				// Successfully created lock file
				_, err = f.WriteString(strconv.Itoa(fl.pid))
				f.Close()
				return err
			}

			// Check if lock file is stale (older than 10 seconds)
			if info, statErr := os.Stat(fl.lockPath); statErr == nil {
				if time.Since(info.ModTime()) > 10*time.Second {
					// Lock file is stale, remove it and try again
					os.Remove(fl.lockPath)
				}
			}
		}
	}
}

// Unlock releases the exclusive lock by removing the lock file
func (fl *FileLock) Unlock() error {
	return os.Remove(fl.lockPath)
}

// Close is an alias for Unlock for compatibility
func (fl *FileLock) Close() error {
	// Ignore error if lock file doesn't exist (already unlocked)
	err := fl.Unlock()
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
