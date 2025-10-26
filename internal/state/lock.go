package state

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// FileLock represents an exclusive file lock using flock
type FileLock struct {
	file *os.File
}

// NewFileLock creates a new file lock for the given path.
// It will create the file if it doesn't exist.
func NewFileLock(path string) (*FileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	return &FileLock{file: file}, nil
}

// Lock acquires an exclusive lock on the file.
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
			err := syscall.Flock(int(fl.file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				return nil
			}
			// If error is EWOULDBLOCK, the lock is held by another process, retry
			if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
				return fmt.Errorf("failed to acquire lock: %w", err)
			}
		}
	}
}

// Unlock releases the exclusive lock on the file
func (fl *FileLock) Unlock() error {
	return syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN)
}

// Close unlocks and closes the file
func (fl *FileLock) Close() error {
	if err := fl.Unlock(); err != nil {
		fl.file.Close()
		return err
	}
	return fl.file.Close()
}
