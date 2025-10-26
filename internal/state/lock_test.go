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

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after Unlock()")
	}
}

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

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after Close()")
	}

	if err := fl.Close(); err != nil {
		t.Fatalf("second Close() returned an error: %v", err)
	}
}

func TestFileLock_Contention(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	fl1, _ := NewFileLock(lockPath)
	fl2, _ := NewFileLock(lockPath)

	var wg sync.WaitGroup
	wg.Add(2)

	g1Locked := make(chan struct{})
	g2AcquiredLock := make(chan struct{})

	go func() {
		defer wg.Done()
		if err := fl1.Lock(); err != nil {
			t.Errorf("g1: Lock() error = %v", err)
			return
		}
		close(g1Locked) // Signal that g1 has the lock

		// Hold the lock for a short time to force g2 to wait
		time.Sleep(100 * time.Millisecond)

		if err := fl1.Unlock(); err != nil {
			t.Errorf("g1: Unlock() error = %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		<-g1Locked // Wait until g1 has the lock

		startTime := time.Now()
		if err := fl2.Lock(); err != nil {
			t.Errorf("g2: Lock() error = %v", err)
			return
		}
		elapsed := time.Since(startTime)
		close(g2AcquiredLock) // Signal that g2 got the lock

		// Check that g2 actually waited
		if elapsed < 90*time.Millisecond { // Give some buffer
			t.Errorf("g2 did not wait for g1 to unlock; elapsed = %v", elapsed)
		}

		if err := fl2.Unlock(); err != nil {
			t.Errorf("g2: Unlock() error = %v", err)
		}
	}()

	wg.Wait()

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
	defer fl1.Unlock() // Ensure it's unlocked at the end of the test

	// Try to acquire the same lock in another goroutine
	fl2, _ := NewFileLock(lockPath)

	startTime := time.Now()
	err := fl2.Lock()
	elapsed := time.Since(startTime)

	if err == nil {
		t.Fatal("fl2: Lock() did not return an error, expected timeout")
		fl2.Unlock() // Unlock if it somehow succeeded
	}
	if err.Error() != "timeout waiting for file lock" {
		t.Errorf("fl2: Lock() returned wrong error: got %q, want %q", err.Error(), "timeout waiting for file lock")
	}

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
	staleTime := time.Now().Add(-15 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set stale time: %v", err)
	}

	// Try to acquire the lock
	fl, _ := NewFileLock(lockPath)
	if err := fl.Lock(); err != nil {
		t.Fatalf("Lock() failed to acquire stale lock: %v", err)
	}

	// Verify the new lock file has the current PID
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
