package state

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	lru "github.com/patrickmn/go-cache"
)

func TestGetState(t *testing.T) {
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache.Set("9.9.9.9", true, lru.DefaultExpiration)

	state := GetState(verifiedCache.Items())

	if len(state.Verified) != 1 {
		t.Errorf("Expected 1 verified entry, got %d", len(state.Verified))
	}
	if state.Verified["9.9.9.9"].Value != true {
		t.Error("Expected 9.9.9.9 to be verified")
	}
	if state.Verified["9.9.9.9"].Expiration == 0 {
		t.Error("Expected non-zero expiration for verified 9.9.9.9")
	}

	if len(state.Memory) != 1 {
		t.Errorf("Expected 1 memory entry, got %d", len(state.Memory))
	}
	if state.Memory["verified"] == 0 {
		t.Error("Expected non-zero memory for verified cache")
	}
}

func TestGetStateEmpty(t *testing.T) {
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

	state := GetState(verifiedCache.Items())

	if len(state.Verified) != 0 {
		t.Errorf("Expected 0 verified entries, got %d", len(state.Verified))
	}
	if len(state.Memory) != 1 {
		t.Errorf("Expected 1 memory entry, got %d", len(state.Memory))
	}
}

func TestSetState(t *testing.T) {
	now := time.Now().UnixNano()
	futureExpiration := now + int64(1*time.Hour)
	pastExpiration := now - int64(1*time.Hour)

	state := State{
		Verified: map[string]CacheEntry{
			"9.9.9.9": {Value: true, Expiration: futureExpiration},
			"8.8.8.8": {Value: true, Expiration: pastExpiration},
			"7.7.7.7": {Value: true, Expiration: 0},
		},
	}

	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
	SetState(state, verifiedCache)

	if verifiedCache.ItemCount() != 2 {
		t.Errorf("Expected 2 verified entries (1 expired filtered out), got %d", verifiedCache.ItemCount())
	}
	if v, ok := verifiedCache.Get("9.9.9.9"); !ok || v.(bool) != true {
		t.Error("Expected 9.9.9.9 to be verified")
	}
	if v, ok := verifiedCache.Get("7.7.7.7"); !ok || v.(bool) != true {
		t.Error("Expected 7.7.7.7 to be verified (no expiration)")
	}
	if _, ok := verifiedCache.Get("8.8.8.8"); ok {
		t.Error("Expected expired entry 8.8.8.8 to be filtered out")
	}
}

func TestSaveStateToFileWithMetrics(t *testing.T) {
	t.Run("Basic save", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache.Set("5.6.7.8", true, lru.DefaultExpiration)

		metrics, err := SaveStateToFileWithMetrics(
			tmpFile,
			verifiedCache,
			testLogger(),
		)
		if err != nil {
			t.Fatalf("SaveStateToFile failed: %v", err)
		}

		if metrics.LockMs < 0 || metrics.MarshalMs < 0 || metrics.WriteMs < 0 || metrics.TotalMs < 0 {
			t.Error("Expected all timing metrics to be non-negative")
		}

		fileInfo, err := os.Stat(tmpFile)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}
		if fileInfo.Size() == 0 {
			t.Error("State file is empty")
		}
		if mode := fileInfo.Mode().Perm(); mode != 0600 {
			t.Fatalf("State file mode = %v, want 0600", mode)
		}

		savedData, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("Failed to read saved file: %v", err)
		}

		var savedState State
		if err := json.Unmarshal(savedData, &savedState); err != nil {
			t.Fatalf("Failed to unmarshal saved state: %v", err)
		}
		if len(savedState.Verified) != 1 {
			t.Errorf("Expected 1 verified entry, got %d", len(savedState.Verified))
		}
	})

	t.Run("Save with metrics", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache.Set("5.6.7.8", true, lru.DefaultExpiration)

		metrics, err := SaveStateToFileWithMetrics(
			tmpFile,
			verifiedCache,
			testLogger(),
		)
		if err != nil {
			t.Fatalf("SaveStateToFileWithMetrics failed: %v", err)
		}

		if metrics.VerifiedEntries != 1 {
			t.Errorf("Expected 1 verified entry, got %d", metrics.VerifiedEntries)
		}
		if matches, err := filepath.Glob(tmpFile + ".tmp-*"); err != nil || len(matches) != 0 {
			t.Fatalf("Expected no leftover temp files, matches=%v err=%v", matches, err)
		}
	})

	t.Run("File write error", func(t *testing.T) {
		invalidPath := "/invalid/directory/that/does/not/exist/state.json"
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		_, err := SaveStateToFileWithMetrics(
			invalidPath,
			verifiedCache,
			testLogger(),
		)
		if err == nil {
			t.Error("Expected error for invalid file path, got nil")
		}
	})
}

func TestLoadStateFromFile(t *testing.T) {
	t.Run("Load valid state file", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		now := time.Now().UnixNano()
		futureExpiration := now + int64(1*time.Hour)
		testState := map[string]interface{}{
			"verified": map[string]CacheEntry{
				"5.6.7.8": {Value: true, Expiration: futureExpiration},
			},
			"memory": map[string]uintptr{"verified": 8},
		}

		data, _ := json.Marshal(testState)
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Fatalf("Failed to write test state: %v", err)
		}

		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		if err := LoadStateFromFile(tmpFile, verifiedCache); err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}

		if verifiedCache.ItemCount() != 1 {
			t.Errorf("Expected 1 verified entry, got %d", verifiedCache.ItemCount())
		}
		if v, ok := verifiedCache.Get("5.6.7.8"); !ok || v.(bool) != true {
			t.Error("Expected 5.6.7.8 to be verified")
		}
	})

	t.Run("Load expired entries", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		now := time.Now().UnixNano()
		pastExpiration := now - int64(1*time.Hour)
		testState := State{
			Verified: map[string]CacheEntry{
				"5.6.7.8": {Value: true, Expiration: pastExpiration},
			},
			Memory: map[string]uintptr{"verified": 8},
		}

		data, _ := json.Marshal(testState)
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Fatalf("Unable to write file: %v", err)
		}

		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		if err := LoadStateFromFile(tmpFile, verifiedCache); err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}
		if verifiedCache.ItemCount() != 0 {
			t.Errorf("Expected 0 entries (expired filtered out), got %d", verifiedCache.ItemCount())
		}
	})

	t.Run("File does not exist", func(t *testing.T) {
		nonExistentFile := t.TempDir() + "/does-not-exist.json"
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		if err := LoadStateFromFile(nonExistentFile, verifiedCache); err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		tmpFile := t.TempDir() + "/invalid.json"
		if err := os.WriteFile(tmpFile, []byte(`{invalid json`), 0644); err != nil {
			t.Fatalf("Failed to write invalid JSON: %v", err)
		}

		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		if err := LoadStateFromFile(tmpFile, verifiedCache); err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
		if verifiedCache.ItemCount() != 0 {
			t.Error("Expected empty cache after failed load")
		}
	})

	t.Run("Empty file", func(t *testing.T) {
		tmpFile := t.TempDir() + "/empty.json"
		if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}

		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
		if err := LoadStateFromFile(tmpFile, verifiedCache); err != nil {
			t.Errorf("Unexpected error for empty file: %v", err)
		}
		if verifiedCache.ItemCount() != 0 {
			t.Error("Expected empty cache after loading empty file")
		}
	})
}

func TestSaveStateToFileWithMetricsWriteError(t *testing.T) {
	statePath := t.TempDir()

	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache.Set("5.6.7.8", true, lru.DefaultExpiration)

	metrics, err := SaveStateToFileWithMetrics(
		statePath,
		verifiedCache,
		testLogger(),
	)
	if err == nil {
		t.Fatal("expected write error when state path is a directory")
	}
	if metrics.VerifiedEntries != 1 {
		t.Fatalf("expected metrics to include marshaled verified entry, got %d", metrics.VerifiedEntries)
	}
}

func TestAtomicWriteStateFileCreateTempError(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "missing")
	_, _, err := atomicWriteStateFile(filepath.Join(missingDir, "state.json"), nil, 0600)
	if err == nil {
		t.Fatal("expected atomicWriteStateFile to fail when temp directory is missing")
	}
}

func TestWriteStateJSON(t *testing.T) {
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache.Set("9.9.9.9", true, lru.DefaultExpiration)
	verifiedCache.Set("bad\a-key", true, lru.DefaultExpiration)

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	if err := writeStateJSON(writer, verifiedCache.Items()); err != nil {
		t.Fatalf("writeStateJSON failed: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	var saved State
	if err := json.Unmarshal(buf.Bytes(), &saved); err != nil {
		t.Fatalf("state JSON did not unmarshal: %v", err)
	}
	if len(saved.Verified) != 2 {
		t.Fatalf("unexpected verified count: %d", len(saved.Verified))
	}
	if saved.Verified["bad\a-key"].Value != true {
		t.Fatal("expected JSON-escaped verified key to round-trip")
	}
}

func TestWriteStateJSONUnexpectedType(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	err := writeStateJSON(
		writer,
		map[string]lru.Item{"bad": {Object: "not-a-bool", Expiration: time.Now().Add(time.Hour).UnixNano()}},
	)
	if err == nil {
		t.Fatal("expected writeStateJSON to reject unexpected cache value type")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))
}

func TestSetStateWithExpiration_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()

		state := State{
			Verified: map[string]CacheEntry{
				"9.9.9.9": {
					Value:      true,
					Expiration: 0,
				},
				"8.8.8.8": {
					Value:      true,
					Expiration: start.Add(5 * time.Second).UnixNano(),
				},
			},
		}

		verifiedCache := lru.New(1*time.Hour, lru.NoExpiration)
		SetState(state, verifiedCache)

		if verifiedCache.ItemCount() != 2 {
			t.Errorf("Expected 2 verified entries, got %d", verifiedCache.ItemCount())
		}

		time.Sleep(6 * time.Second)
		synctest.Wait()

		if _, found := verifiedCache.Get("8.8.8.8"); found {
			t.Error("Verified entry 8.8.8.8 should have expired after 5 seconds")
		}
		if _, found := verifiedCache.Get("9.9.9.9"); !found {
			t.Error("Verified entry with no expiration should still be present")
		}
	})
}

func TestSaveAndLoadStateWithExpiration_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		verifiedCache1 := lru.New(1*time.Hour, lru.NoExpiration)
		verifiedCache1.Set("8.8.8.8", true, 5*time.Second)
		verifiedCache1.Set("9.9.9.9", true, lru.NoExpiration)

		if _, err := SaveStateToFileWithMetrics(
			tmpFile,
			verifiedCache1,
			testLogger(),
		); err != nil {
			t.Fatalf("SaveStateToFile failed: %v", err)
		}

		time.Sleep(4 * time.Second)
		synctest.Wait()

		verifiedCache2 := lru.New(1*time.Hour, lru.NoExpiration)
		if err := LoadStateFromFile(tmpFile, verifiedCache2); err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}

		if _, found := verifiedCache2.Get("8.8.8.8"); !found {
			t.Error("Verified entry 8.8.8.8 should be loaded before expiration")
		}
		if _, found := verifiedCache2.Get("9.9.9.9"); !found {
			t.Error("Verified entry with no expiration should be loaded")
		}

		time.Sleep(2 * time.Second)
		synctest.Wait()

		if _, found := verifiedCache2.Get("8.8.8.8"); found {
			t.Error("Verified entry 8.8.8.8 should have expired")
		}
	})
}

// TestCacheCleanupInterval_Synctest verifies go-cache cleanup runs on schedule
// NOTE: This test is skipped because it tests the janitor goroutine which is incompatible with synctest
func TestCacheCleanupInterval_Synctest(t *testing.T) {
	t.Skip("Skipping test that requires janitor goroutine (incompatible with synctest)")
	synctest.Test(t, func(t *testing.T) {
		cleanupInterval := 1 * time.Minute
		cache := lru.New(5*time.Second, cleanupInterval)

		cache.Set("test-key", uint(42), 3*time.Second)

		if _, found := cache.Get("test-key"); !found {
			t.Fatal("Entry should exist immediately after Set")
		}

		time.Sleep(4 * time.Second)
		synctest.Wait()

		if _, found := cache.Get("test-key"); found {
			t.Error("Entry should be expired after 3 seconds")
		}

		time.Sleep(57 * time.Second)
		synctest.Wait()

		if cache.ItemCount() != 0 {
			t.Errorf("Cache should be empty after cleanup, got %d items", cache.ItemCount())
		}
	})
}
