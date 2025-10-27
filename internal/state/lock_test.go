// File: filelock_test.go
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
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

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatal("lock file was not removed after Close()")
	}

	// Close again (should be idempotent and not return an error)
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

	// Goroutine 1: Acquires lock first, holds it, then releases
	go func() {
		defer wg.Done()
		if err := fl1.Lock(); err != nil {
			t.Errorf("g1: Lock() error = %v", err)
			return
		}
		close(g1Locked)

		time.Sleep(100 * time.Millisecond)

		if err := fl1.Unlock(); err != nil {
			t.Errorf("g1: Unlock() error = %v", err)
		}
	}()

	// Goroutine 2: Waits for g1 to get the lock, then tries to acquire it
	go func() {
		defer wg.Done()
		<-g1Locked

		startTime := time.Now()
		if err := fl2.Lock(); err != nil {
			t.Errorf("g2: Lock() error = %v", err)
			return
		}
		elapsed := time.Since(startTime)

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
	// Defer a Close() for cleanup. This is safer now.
	defer fl1.Close()

	// Try to acquire the same lock in another goroutine
	fl2, _ := NewFileLock(lockPath)

	startTime := time.Now()
	err := fl2.Lock()
	elapsed := time.Since(startTime)

	if err == nil {
		t.Fatal("fl2: Lock() did not return an error, expected timeout")
		fl2.Unlock() //nolint:errcheck
		return
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

	staleTime := time.Now().Add(-15 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set stale time: %v", err)
	}

	fl, _ := NewFileLock(lockPath)
	if err := fl.Lock(); err != nil {
		t.Fatalf("Lock() failed to acquire stale lock: %v", err)
	}
	defer fl.Unlock() //nolint:errcheck

	content, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("could not read new lock file: %v", err)
	}
	expectedPID := strconv.Itoa(os.Getpid())
	if string(content) != expectedPID {
		t.Errorf("lock file not overwritten with new PID: got %q, want %q", string(content), expectedPID)
	}
}

// TestFileLock_StaleLockRace tests for a "Check-Then-Act" race condition
// when multiple processes detect a stale lock at the same time.
func TestFileLock_StaleLockRace(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	if err := os.WriteFile(lockPath, []byte("stale-pid"), 0644); err != nil {
		t.Fatalf("failed to create stale lock file: %v", err)
	}
	staleTime := time.Now().Add(-15 * time.Second)
	if err := os.Chtimes(lockPath, staleTime, staleTime); err != nil {
		t.Fatalf("failed to set stale time: %v", err)
	}

	numGoroutines := 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	readyGate := &sync.WaitGroup{}
	readyGate.Add(numGoroutines)
	releaseGate := &sync.WaitGroup{}
	releaseGate.Add(1)

	var activeLocks int32
	var maxActiveLocks int32

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			readyGate.Done()
			releaseGate.Wait()

			fl, err := NewFileLock(lockPath)
			if err != nil {
				return
			}

			// We expect most of these to fail with a timeout, which is fine.
			// The critical part is that they don't *all* succeed.
			if err := fl.Lock(); err != nil {
				return
			}

			// --- CRITICAL SECTION ---
			currentActive := atomic.AddInt32(&activeLocks, 1)
			if current := atomic.LoadInt32(&maxActiveLocks); current < currentActive {
				atomic.CompareAndSwapInt32(&maxActiveLocks, current, currentActive)
			}

			time.Sleep(10 * time.Millisecond)

			atomic.AddInt32(&activeLocks, -1)
			// --- END CRITICAL SECTION ---

			fl.Unlock() //nolint:errcheck
		}()
	}

	readyGate.Wait()
	releaseGate.Done()
	wg.Wait()

	finalMax := atomic.LoadInt32(&maxActiveLocks)
	if finalMax > 1 {
		t.Errorf("RACE CONDITION DETECTED: %d goroutines held the lock simultaneously", finalMax)
	}

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Error("lock file was not removed after test completion")
		os.Remove(lockPath) //nolint:errcheck
	}
}

// --- NEW TESTS ---

// TestFileLock_UnlockSafety verifies that a lock cannot be unlocked by
// a process that does not own it (PID mismatch).
func TestFileLock_UnlockSafety(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	// Create a lock file manually with a fake PID
	fakePID := "-12345"
	if err := os.WriteFile(lockPath, []byte(fakePID), 0644); err != nil {
		t.Fatalf("failed to create fake lock file: %v", err)
	}
	defer os.Remove(lockPath) //nolint:errcheck

	fl, err := NewFileLock(lockPath)
	if err != nil {
		t.Fatalf("NewFileLock() error = %v", err)
	}

	// Try to Unlock() a file we don't own
	err = fl.Unlock()
	if err == nil {
		t.Fatal("Unlock() did not return an error when PID did not match")
	}

	// Check for the specific error
	expectedErr := fmt.Sprintf("cannot unlock file held by different process (my_pid: %d, lock_pid: %s)", fl.pid, fakePID)
	if err.Error() != expectedErr {
		t.Errorf("Unlock() returned wrong error: \ngot:  %q\nwant: %q", err.Error(), expectedErr)
	}

	// Crucially, verify the lock file was NOT deleted
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file was removed by unsafe Unlock(): %v", err)
	}
}

// TestFileLock_CloseSafety verifies that Close() does not return an error
// and does not delete the lock file if it's owned by another process.
func TestFileLock_CloseSafety(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	lockPath := filepath.Join(tempDir, "test.lock")

	// Create a lock file manually with a fake PID
	fakePID := "-12345"
	if err := os.WriteFile(lockPath, []byte(fakePID), 0644); err != nil {
		t.Fatalf("failed to create fake lock file: %v", err)
	}
	defer os.Remove(lockPath) //nolint:errcheck

	fl, err := NewFileLock(lockPath)
	if err != nil {
		t.Fatalf("NewFileLock() error = %v", err)
	}

	// Try to Close() a file we don't own
	err = fl.Close()
	if err != nil {
		t.Fatalf("Close() returned an error when PID did not match: %v", err)
	}

	// Verify the lock file was NOT deleted
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file was removed by unsafe Close(): %v", err)
	}
}
