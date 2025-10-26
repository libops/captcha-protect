// File: filelock_test.go
package state

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestFileLock_LockUnlock tests the basic Lock and Unlock functionality.
func TestFileLock_LockUnlock(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	fl, err := NewFileLock(lockPath)
	if err != nil {
		t.Fatalf("NewFileLock() error = %v", err)
	}

	if err := fl.Lock(); err != nil {
		t.Fatalf("Lock() error = %v", err)
	}

	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file was not created: %v", err)
	}

	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("could not read lock file: %v", err)
	}
	expectedPID := strconv.Itoa(os.Getpid())
	if string(content) != expectedPID {
		t.Errorf("lock file contains wrong PID: got %q, want %q", string(content), expectedPID)
	}

	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}

	// Check that lock file is removed
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after Unlock()")
	}
}

// TestFileLock_Close tests the Close functionality, including idempotency.
func TestFileLock_Close(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	fl, err := NewFileLock(lockPath)
	if err != nil {
		t.Fatalf("NewFileLock() error = %v", err)
	}

	if err := fl.Lock(); err != nil {
		t.Fatalf("Lock() error = %v", err)
	}

	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file was not created: %v", err)
	}

	if err := fl.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Check that lock file is removed
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after Close()")
	}

	// Close again (should be idempotent and not return an error)
	// This confirms the os.IsNotExist(err) check in Close() is working.
	if err := fl.Close(); err != nil {
		t.Fatalf("second Close() returned an error: %v", err)
	}
}

// TestFileLock_Contention tests that a second process waits for the first to unlock.
func TestFileLock_Contention(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	fl1, _ := NewFileLock(lockPath)
	fl2, _ := NewFileLock(lockPath)

	var wg sync.WaitGroup
	wg.Add(2)

	// Use channels to synchronize the goroutines and ensure
	// g2 doesn't try to lock until g1 *definitely* has the lock.
	g1Locked := make(chan struct{})
	g2AcquiredLock := make(chan struct{})

	// Goroutine 1: Acquires lock first, holds it, then releases
	go func() {
		defer wg.Done()
		if err := fl1.Lock(); err != nil {
			t.Errorf("g1: Lock() error = %v", err)
			return
		}
		// Signal that g1 has the lock
		close(g1Locked)

		// Hold the lock for a short time to force g2 to wait
		time.Sleep(100 * time.Millisecond)

		if err := fl1.Unlock(); err != nil {
			t.Errorf("g1: Unlock() error = %v", err)
		}
	}()

	// Goroutine 2: Waits for g1 to get the lock, then tries to acquire it
	go func() {
		defer wg.Done()
		// Wait until g1 has the lock
		<-g1Locked

		startTime := time.Now()
		if err := fl2.Lock(); err != nil {
			t.Errorf("g2: Lock() error = %v", err)
			return
		}
		elapsed := time.Since(startTime)
		// Signal that g2 got the lock
		close(g2AcquiredLock)

		// Check that g2 actually waited
		if elapsed < 90*time.Millisecond { // Give some buffer
			t.Errorf("g2 did not wait for g1 to unlock; elapsed = %v", elapsed)
		}

		if err := fl2.Unlock(); err != nil {
			t.Errorf("g2: Unlock() error = %v", err)
		}
	}()

	wg.Wait()

	// Final check: ensure the lock file is gone
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after all goroutines finished")
	}
}

// TestFileLock_Timeout tests that Lock() returns an error if it can't
// acquire the lock within the timeout period.
func TestFileLock_Timeout(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	fl1, _ := NewFileLock(lockPath)
	if err := fl1.Lock(); err != nil {
		t.Fatalf("fl1: Lock() error = %v", err)
	}

	defer func() {
		if err := fl1.Unlock(); err != nil {
			// Use t.Errorf, not t.Fatalf, as this is a cleanup operation
			// and the primary test logic may have already passed or failed.
			t.Errorf("fl1: Unlock() error during cleanup = %v", err)
		}
	}()

	// Try to acquire the same lock in another goroutine
	fl2, _ := NewFileLock(lockPath)

	startTime := time.Now()
	err := fl2.Lock()
	elapsed := time.Since(startTime)

	// Check for timeout error
	if err == nil {
		// This is the failure case for this test. We expected an error but got none.
		t.Fatal("fl2: Lock() did not return an error, expected timeout")

		if err := fl2.Unlock(); err != nil {
			t.Errorf("fl2: Unlock() error after unexpected success = %v", err)
		}
		return // Stop the test here as it's already failed.
	}
	if err.Error() != "timeout waiting for file lock" {
		t.Errorf("fl2: Lock() returned wrong error: got %q, want %q", err.Error(), "timeout waiting for file lock")
	}

	// Check that it waited for approximately 5 seconds
	if elapsed < 4*time.Second || elapsed > 6*time.Second {
		t.Errorf("fl2: timeout duration was not ~5s: got %v", elapsed)
	}
}

// TestFileLock_StaleLock tests that a lock file older than 10 seconds is removed.
func TestFileLock_StaleLock(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	if err := os.WriteFile(lockPath, []byte("12345"), 0644); err != nil {
		t.Fatalf("failed to create stale lock file: %v", err)
	}

	// Set its modification time to 15 seconds in the past
	// This simulates a lock file left by a crashed process.
	staleTime := time.Now().Add(-15 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set stale time: %v", err)
	}

	// Try to acquire the lock
	// The Lock() function should see the stale ModTime and remove the file.
	fl, _ := NewFileLock(lockPath)
	if err := fl.Lock(); err != nil {
		t.Fatalf("Lock() failed to acquire stale lock: %v", err)
	}

	// Verify the new lock file has the current PID
	// This proves that our process acquired the lock, not the old "stale" one.
	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("could not read new lock file: %v", err)
	}
	expectedPID := strconv.Itoa(os.Getpid())
	if string(content) != expectedPID {
		t.Errorf("lock file not overwritten with new PID: got %q, want %q", string(content), expectedPID)
	}

	if err := fl.Unlock(); err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
}
