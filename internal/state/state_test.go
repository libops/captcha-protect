package state

import (
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"testing/synctest"
	"time"

	lru "github.com/patrickmn/go-cache"
)

func TestGetState(t *testing.T) {
	// Create test caches
	rateCache := lru.New(1*time.Hour, 1*time.Minute)
	botCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

	// Add test data
	rateCache.Set("192.168.0.0", uint(10), lru.DefaultExpiration)
	rateCache.Set("10.0.0.0", uint(5), lru.DefaultExpiration)

	botCache.Set("1.2.3.4", true, lru.DefaultExpiration)
	botCache.Set("5.6.7.8", false, lru.DefaultExpiration)

	verifiedCache.Set("9.9.9.9", true, lru.DefaultExpiration)

	// Get state
	state := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())

	// Verify rate cache data
	if len(state.Rate) != 2 {
		t.Errorf("Expected 2 rate entries, got %d", len(state.Rate))
	}
	if state.Rate["192.168.0.0"].Value != uint(10) {
		t.Errorf("Expected rate 10 for 192.168.0.0, got %v", state.Rate["192.168.0.0"].Value)
	}
	if state.Rate["10.0.0.0"].Value != uint(5) {
		t.Errorf("Expected rate 5 for 10.0.0.0, got %v", state.Rate["10.0.0.0"].Value)
	}
	// Verify expiration timestamps are set
	if state.Rate["192.168.0.0"].Expiration == 0 {
		t.Error("Expected non-zero expiration for 192.168.0.0")
	}

	// Verify bot cache data
	if len(state.Bots) != 2 {
		t.Errorf("Expected 2 bot entries, got %d", len(state.Bots))
	}
	if state.Bots["1.2.3.4"].Value != true {
		t.Error("Expected bot 1.2.3.4 to be true")
	}
	if state.Bots["5.6.7.8"].Value != false {
		t.Error("Expected bot 5.6.7.8 to be false")
	}
	// Verify expiration timestamps are set
	if state.Bots["1.2.3.4"].Expiration == 0 {
		t.Error("Expected non-zero expiration for bot 1.2.3.4")
	}

	// Verify verified cache data
	if len(state.Verified) != 1 {
		t.Errorf("Expected 1 verified entry, got %d", len(state.Verified))
	}
	if state.Verified["9.9.9.9"].Value != true {
		t.Error("Expected 9.9.9.9 to be verified")
	}
	// Verify expiration timestamp is set
	if state.Verified["9.9.9.9"].Expiration == 0 {
		t.Error("Expected non-zero expiration for verified 9.9.9.9")
	}

	// Verify memory tracking exists
	if len(state.Memory) != 3 {
		t.Errorf("Expected 3 memory entries, got %d", len(state.Memory))
	}
	if state.Memory["rate"] == 0 {
		t.Error("Expected non-zero memory for rate cache")
	}
	if state.Memory["bot"] == 0 {
		t.Error("Expected non-zero memory for bot cache")
	}
	if state.Memory["verified"] == 0 {
		t.Error("Expected non-zero memory for verified cache")
	}
}

func TestGetStateEmpty(t *testing.T) {
	// Create empty caches
	rateCache := lru.New(1*time.Hour, 1*time.Minute)
	botCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

	state := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())

	if len(state.Rate) != 0 {
		t.Errorf("Expected 0 rate entries, got %d", len(state.Rate))
	}
	if len(state.Bots) != 0 {
		t.Errorf("Expected 0 bot entries, got %d", len(state.Bots))
	}
	if len(state.Verified) != 0 {
		t.Errorf("Expected 0 verified entries, got %d", len(state.Verified))
	}
	if len(state.Memory) != 3 {
		t.Errorf("Expected 3 memory entries, got %d", len(state.Memory))
	}
}

func TestSetState(t *testing.T) {
	// Create state with expiration times
	now := time.Now().UnixNano()
	futureExpiration := now + int64(1*time.Hour)
	pastExpiration := now - int64(1*time.Hour)

	state := State{
		Rate: map[string]CacheEntry{
			"192.168.0.0": {Value: uint(10), Expiration: futureExpiration},
			"10.0.0.0":    {Value: uint(5), Expiration: pastExpiration}, // expired
		},
		Bots: map[string]CacheEntry{
			"1.2.3.4": {Value: true, Expiration: futureExpiration},
			"5.6.7.8": {Value: false, Expiration: pastExpiration}, // expired
		},
		Verified: map[string]CacheEntry{
			"9.9.9.9": {Value: true, Expiration: futureExpiration},
			"8.8.8.8": {Value: true, Expiration: pastExpiration}, // expired
			"7.7.7.7": {Value: true, Expiration: 0},              // no expiration
		},
	}

	// Create caches
	rateCache := lru.New(1*time.Hour, 1*time.Minute)
	botCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

	// Set state
	SetState(state, rateCache, botCache, verifiedCache)

	// Verify only non-expired entries were loaded
	if rateCache.ItemCount() != 1 {
		t.Errorf("Expected 1 rate entry (expired filtered out), got %d", rateCache.ItemCount())
	}
	if v, ok := rateCache.Get("192.168.0.0"); !ok || v.(uint) != 10 {
		t.Error("Expected rate 10 for 192.168.0.0")
	}
	if _, ok := rateCache.Get("10.0.0.0"); ok {
		t.Error("Expected expired entry 10.0.0.0 to be filtered out")
	}

	if botCache.ItemCount() != 1 {
		t.Errorf("Expected 1 bot entry (expired filtered out), got %d", botCache.ItemCount())
	}
	if v, ok := botCache.Get("1.2.3.4"); !ok || v.(bool) != true {
		t.Error("Expected bot 1.2.3.4 to be true")
	}

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

func TestReconcileState(t *testing.T) {
	now := time.Now().UnixNano()
	oldExpiration := now + int64(30*time.Minute)
	newExpiration := now + int64(1*time.Hour)

	// Create file state with some entries
	fileState := State{
		Rate: map[string]CacheEntry{
			"192.168.0.0": {Value: uint(15), Expiration: newExpiration}, // newer than memory
			"10.0.0.0":    {Value: uint(3), Expiration: oldExpiration},  // older than memory
			"172.16.0.0":  {Value: uint(7), Expiration: newExpiration},  // only in file
		},
		Verified: map[string]CacheEntry{
			"1.1.1.1": {Value: true, Expiration: newExpiration}, // only in file
			"2.2.2.2": {Value: true, Expiration: oldExpiration}, // older than memory
		},
	}

	// Create memory caches with some overlapping data
	rateCache := lru.New(1*time.Hour, 1*time.Minute)
	botCache := lru.New(1*time.Hour, 1*time.Minute)
	verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

	rateCache.Set("192.168.0.0", uint(10), time.Duration(oldExpiration-now)) // older, should be replaced
	rateCache.Set("10.0.0.0", uint(5), time.Duration(newExpiration-now))     // newer, should be kept
	rateCache.Set("8.8.8.8", uint(20), time.Duration(newExpiration-now))     // only in memory

	verifiedCache.Set("2.2.2.2", true, time.Duration(newExpiration-now)) // newer, should be kept

	// Reconcile
	ReconcileState(fileState, rateCache, botCache, verifiedCache)

	// Verify reconciliation results
	// 192.168.0.0 should be updated to file's value (newer expiration)
	if v, ok := rateCache.Get("192.168.0.0"); !ok || v.(uint) != 15 {
		t.Errorf("Expected rate 15 for 192.168.0.0 after reconciliation, got %v", v)
	}

	// 10.0.0.0 should keep memory value (newer expiration)
	if v, ok := rateCache.Get("10.0.0.0"); !ok || v.(uint) != 5 {
		t.Errorf("Expected rate 5 for 10.0.0.0 (memory kept), got %v", v)
	}

	// 172.16.0.0 should be added from file
	if v, ok := rateCache.Get("172.16.0.0"); !ok || v.(uint) != 7 {
		t.Error("Expected 172.16.0.0 to be added from file")
	}

	// 8.8.8.8 should still exist (only in memory)
	if v, ok := rateCache.Get("8.8.8.8"); !ok || v.(uint) != 20 {
		t.Error("Expected 8.8.8.8 to still exist in memory")
	}

	// 1.1.1.1 should be added from file
	if v, ok := verifiedCache.Get("1.1.1.1"); !ok || v.(bool) != true {
		t.Error("Expected 1.1.1.1 to be added from file")
	}

	// 2.2.2.2 should keep memory value (newer expiration)
	if v, ok := verifiedCache.Get("2.2.2.2"); !ok || v.(bool) != true {
		t.Error("Expected 2.2.2.2 to be kept from memory")
	}
}

func TestSaveStateToFile(t *testing.T) {
	t.Run("Basic save without reconciliation", func(t *testing.T) {
		// Create temp file
		tmpFile := t.TempDir() + "/state.json"

		// Create caches with test data
		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		rateCache.Set("192.168.0.0", uint(10), lru.DefaultExpiration)
		botCache.Set("1.2.3.4", false, lru.DefaultExpiration)
		verifiedCache.Set("5.6.7.8", true, lru.DefaultExpiration)

		// Save without reconciliation
		lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs, err := SaveStateToFile(
			tmpFile,
			false, // no reconciliation
			rateCache,
			botCache,
			verifiedCache,
			testLogger(),
		)

		if err != nil {
			t.Fatalf("SaveStateToFile failed: %v", err)
		}

		// Verify timing metrics
		if lockMs < 0 || readMs < 0 || reconcileMs < 0 || marshalMs < 0 || writeMs < 0 || totalMs < 0 {
			t.Error("Expected all timing metrics to be non-negative")
		}

		// Verify reconcileMs is 0 when reconciliation is disabled
		if reconcileMs != 0 {
			t.Errorf("Expected reconcileMs to be 0 when reconciliation disabled, got %d", reconcileMs)
		}

		// Verify readMs is 0 when reconciliation is disabled
		if readMs != 0 {
			t.Errorf("Expected readMs to be 0 when reconciliation disabled, got %d", readMs)
		}

		// Verify file was created and contains data
		fileInfo, err := os.Stat(tmpFile)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}
		if fileInfo.Size() == 0 {
			t.Error("State file is empty")
		}

		// Load and verify the saved data
		savedData, err := os.ReadFile(tmpFile)
		if err != nil {
			t.Fatalf("Failed to read saved file: %v", err)
		}

		var savedState State
		if err := json.Unmarshal(savedData, &savedState); err != nil {
			t.Fatalf("Failed to unmarshal saved state: %v", err)
		}

		if len(savedState.Rate) != 1 {
			t.Errorf("Expected 1 rate entry, got %d", len(savedState.Rate))
		}
		if len(savedState.Bots) != 1 {
			t.Errorf("Expected 1 bot entry, got %d", len(savedState.Bots))
		}
		if len(savedState.Verified) != 1 {
			t.Errorf("Expected 1 verified entry, got %d", len(savedState.Verified))
		}
	})

	t.Run("Save with reconciliation", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		// Create initial state file
		now := time.Now().UnixNano()
		futureExpiration := now + int64(1*time.Hour)
		initialState := State{
			Rate: map[string]CacheEntry{
				"10.0.0.0": {Value: uint(5), Expiration: futureExpiration},
			},
			Bots:     map[string]CacheEntry{},
			Verified: map[string]CacheEntry{},
			Memory:   map[string]uintptr{"rate": 8, "bot": 8, "verified": 8},
		}
		initialData, _ := json.Marshal(initialState)
		if err := os.WriteFile(tmpFile, initialData, 0644); err != nil {
			t.Fatalf("Failed to write initial state: %v", err)
		}

		// Create caches with different data
		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		rateCache.Set("192.168.0.0", uint(10), lru.DefaultExpiration)

		// Save with reconciliation enabled
		lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs, err := SaveStateToFile(
			tmpFile,
			true, // enable reconciliation
			rateCache,
			botCache,
			verifiedCache,
			testLogger(),
		)

		if err != nil {
			t.Fatalf("SaveStateToFile with reconciliation failed: %v", err)
		}

		// Verify timing metrics (all should be non-negative)
		if lockMs < 0 {
			t.Error("Expected non-negative lockMs")
		}
		if readMs < 0 {
			t.Error("Expected non-negative readMs when reconciliation is enabled")
		}
		if reconcileMs < 0 {
			t.Error("Expected non-negative reconcileMs when reconciliation is enabled")
		}
		if marshalMs < 0 {
			t.Error("Expected non-negative marshalMs")
		}
		if writeMs < 0 {
			t.Error("Expected non-negative writeMs")
		}
		if totalMs < 0 {
			t.Error("Expected non-negative totalMs")
		}

		// Verify both entries are in the saved file (reconciled)
		savedData, _ := os.ReadFile(tmpFile)
		var savedState State
		err = json.Unmarshal(savedData, &savedState)
		if err != nil {
			t.Errorf("Unable to unmarshal state %v", err)
		}

		if len(savedState.Rate) != 2 {
			t.Errorf("Expected 2 rate entries after reconciliation, got %d", len(savedState.Rate))
		}
	})

	t.Run("File write error", func(t *testing.T) {
		// Use invalid path to trigger error
		invalidPath := "/invalid/directory/that/does/not/exist/state.json"

		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		_, _, _, _, _, _, err := SaveStateToFile(
			invalidPath,
			false,
			rateCache,
			botCache,
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

		// Create state file
		now := time.Now().UnixNano()
		futureExpiration := now + int64(1*time.Hour)
		testState := State{
			Rate: map[string]CacheEntry{
				"192.168.0.0": {Value: uint(10), Expiration: futureExpiration},
				"10.0.0.0":    {Value: uint(5), Expiration: futureExpiration},
			},
			Bots: map[string]CacheEntry{
				"1.2.3.4": {Value: true, Expiration: futureExpiration},
			},
			Verified: map[string]CacheEntry{
				"5.6.7.8": {Value: true, Expiration: futureExpiration},
			},
			Memory: map[string]uintptr{"rate": 8, "bot": 8, "verified": 8},
		}

		data, _ := json.Marshal(testState)
		if err := os.WriteFile(tmpFile, data, 0644); err != nil {
			t.Fatalf("Failed to write test state: %v", err)
		}

		// Load into empty caches
		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		err := LoadStateFromFile(tmpFile, rateCache, botCache, verifiedCache)
		if err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}

		// Verify caches were populated
		if rateCache.ItemCount() != 2 {
			t.Errorf("Expected 2 rate entries, got %d", rateCache.ItemCount())
		}
		if botCache.ItemCount() != 1 {
			t.Errorf("Expected 1 bot entry, got %d", botCache.ItemCount())
		}
		if verifiedCache.ItemCount() != 1 {
			t.Errorf("Expected 1 verified entry, got %d", verifiedCache.ItemCount())
		}

		// Verify specific values
		if v, ok := rateCache.Get("192.168.0.0"); !ok || v.(uint) != 10 {
			t.Error("Expected rate 10 for 192.168.0.0")
		}
		if v, ok := botCache.Get("1.2.3.4"); !ok || v.(bool) != true {
			t.Error("Expected bot 1.2.3.4 to be true")
		}
		if v, ok := verifiedCache.Get("5.6.7.8"); !ok || v.(bool) != true {
			t.Error("Expected 5.6.7.8 to be verified")
		}
	})

	t.Run("Load expired entries", func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		// Create state with expired entries
		now := time.Now().UnixNano()
		pastExpiration := now - int64(1*time.Hour)
		testState := State{
			Rate: map[string]CacheEntry{
				"192.168.0.0": {Value: uint(10), Expiration: pastExpiration}, // expired
			},
			Bots:     map[string]CacheEntry{},
			Verified: map[string]CacheEntry{},
			Memory:   map[string]uintptr{"rate": 8, "bot": 8, "verified": 8},
		}

		data, _ := json.Marshal(testState)
		err := os.WriteFile(tmpFile, data, 0644)
		if err != nil {
			t.Fatalf("Unable to write file: %v", err)
		}
		// Load into empty caches
		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		err = LoadStateFromFile(tmpFile, rateCache, botCache, verifiedCache)
		if err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}

		// Expired entries should be filtered out
		if rateCache.ItemCount() != 0 {
			t.Errorf("Expected 0 entries (expired filtered out), got %d", rateCache.ItemCount())
		}
	})

	t.Run("File does not exist", func(t *testing.T) {
		nonExistentFile := t.TempDir() + "/does-not-exist.json"

		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		err := LoadStateFromFile(nonExistentFile, rateCache, botCache, verifiedCache)
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		tmpFile := t.TempDir() + "/invalid.json"

		// Write invalid JSON
		if err := os.WriteFile(tmpFile, []byte(`{invalid json`), 0644); err != nil {
			t.Fatalf("Failed to write invalid JSON: %v", err)
		}

		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		err := LoadStateFromFile(tmpFile, rateCache, botCache, verifiedCache)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}

		// Caches should remain empty
		if rateCache.ItemCount() != 0 {
			t.Error("Expected empty cache after failed load")
		}
	})

	t.Run("Empty file", func(t *testing.T) {
		tmpFile := t.TempDir() + "/empty.json"

		// Write empty file
		if err := os.WriteFile(tmpFile, []byte{}, 0644); err != nil {
			t.Fatalf("Failed to write empty file: %v", err)
		}

		rateCache := lru.New(1*time.Hour, 1*time.Minute)
		botCache := lru.New(1*time.Hour, 1*time.Minute)
		verifiedCache := lru.New(1*time.Hour, 1*time.Minute)

		// Empty file returns nil (no state to load, which is fine)
		err := LoadStateFromFile(tmpFile, rateCache, botCache, verifiedCache)
		if err != nil {
			t.Errorf("Unexpected error for empty file: %v", err)
		}

		// Caches should remain empty
		if rateCache.ItemCount() != 0 {
			t.Error("Expected empty cache after loading empty file")
		}
	})
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))
}

// TestSetStateWithExpiration_Synctest uses synctest to verify expiration logic
func TestSetStateWithExpiration_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Initial time: midnight UTC 2000-01-01
		start := time.Now()

		// Create state with entries expiring at different times
		state := State{
			Rate: map[string]CacheEntry{
				"192.168.0.0": {
					Value:      uint(10),
					Expiration: start.Add(5 * time.Second).UnixNano(), // expires in 5s
				},
				"10.0.0.0": {
					Value:      uint(5),
					Expiration: start.Add(10 * time.Second).UnixNano(), // expires in 10s
				},
			},
			Bots: map[string]CacheEntry{
				"1.2.3.4": {
					Value:      true,
					Expiration: start.Add(3 * time.Second).UnixNano(), // expires in 3s
				},
			},
			Verified: map[string]CacheEntry{
				"9.9.9.9": {
					Value:      true,
					Expiration: 0, // never expires
				},
			},
		}

		// Create empty caches (no cleanup interval to avoid background goroutines)
		rateCache := lru.New(1*time.Hour, lru.NoExpiration)
		botCache := lru.New(1*time.Hour, lru.NoExpiration)
		verifiedCache := lru.New(1*time.Hour, lru.NoExpiration)

		// Load state
		SetState(state, rateCache, botCache, verifiedCache)

		// Verify all entries are loaded
		if rateCache.ItemCount() != 2 {
			t.Errorf("Expected 2 rate entries, got %d", rateCache.ItemCount())
		}
		if botCache.ItemCount() != 1 {
			t.Errorf("Expected 1 bot entry, got %d", botCache.ItemCount())
		}
		if verifiedCache.ItemCount() != 1 {
			t.Errorf("Expected 1 verified entry, got %d", verifiedCache.ItemCount())
		}

		// Advance time by 4 seconds (bot entry should expire, rate entries still valid)
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// Bot cache should be empty (expired at 3s)
		if _, found := botCache.Get("1.2.3.4"); found {
			t.Error("Bot entry should have expired after 3 seconds")
		}

		// Rate entries should still be present
		if _, found := rateCache.Get("192.168.0.0"); !found {
			t.Error("Rate entry 192.168.0.0 should not expire until 5 seconds")
		}
		if _, found := rateCache.Get("10.0.0.0"); !found {
			t.Error("Rate entry 10.0.0.0 should not expire until 10 seconds")
		}

		// Advance time by 2 more seconds (total 6s, first rate entry should expire)
		time.Sleep(2 * time.Second)
		synctest.Wait()

		// First rate entry should be expired
		if _, found := rateCache.Get("192.168.0.0"); found {
			t.Error("Rate entry 192.168.0.0 should have expired after 5 seconds")
		}

		// Second rate entry should still be present
		if _, found := rateCache.Get("10.0.0.0"); !found {
			t.Error("Rate entry 10.0.0.0 should not expire until 10 seconds")
		}

		// Verified entry with no expiration should still be present
		if _, found := verifiedCache.Get("9.9.9.9"); !found {
			t.Error("Verified entry with no expiration should never expire")
		}

		// Advance time by 5 more seconds (total 11s, all time-based entries expired)
		time.Sleep(5 * time.Second)
		synctest.Wait()

		// All time-based entries should be expired
		if _, found := rateCache.Get("10.0.0.0"); found {
			t.Error("Rate entry 10.0.0.0 should have expired after 10 seconds")
		}

		// Only the never-expiring verified entry should remain
		if _, found := verifiedCache.Get("9.9.9.9"); !found {
			t.Error("Verified entry with no expiration should still be present after 11 seconds")
		}
	})
}

// TestReconcileStateWithExpiration_Synctest tests reconciliation with time control
func TestReconcileStateWithExpiration_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()

		// Create file state with entries expiring at different times
		fileState := State{
			Rate: map[string]CacheEntry{
				"192.168.0.0": {
					Value:      uint(15),
					Expiration: start.Add(10 * time.Second).UnixNano(), // newer expiration
				},
				"10.0.0.0": {
					Value:      uint(3),
					Expiration: start.Add(5 * time.Second).UnixNano(), // older expiration
				},
			},
		}

		// Create memory caches with overlapping data (no cleanup interval to avoid background goroutines)
		rateCache := lru.New(1*time.Hour, lru.NoExpiration)
		botCache := lru.New(1*time.Hour, lru.NoExpiration)
		verifiedCache := lru.New(1*time.Hour, lru.NoExpiration)

		// Memory entry with older expiration (should be replaced)
		rateCache.Set("192.168.0.0", uint(10), 5*time.Second)
		// Memory entry with newer expiration (should be kept)
		rateCache.Set("10.0.0.0", uint(5), 10*time.Second)

		// Reconcile
		ReconcileState(fileState, rateCache, botCache, verifiedCache)

		// 192.168.0.0 should have file's value (newer expiration)
		if v, ok := rateCache.Get("192.168.0.0"); !ok || v.(uint) != 15 {
			t.Errorf("Expected rate 15 for 192.168.0.0, got %v", v)
		}

		// 10.0.0.0 should have memory's value (newer expiration)
		if v, ok := rateCache.Get("10.0.0.0"); !ok || v.(uint) != 5 {
			t.Errorf("Expected rate 5 for 10.0.0.0 (memory kept), got %v", v)
		}

		// Advance time by 6 seconds
		time.Sleep(6 * time.Second)
		synctest.Wait()

		// Both entries should still be present (both have 10s expiration from reconciliation)
		// - 192.168.0.0 has file's value (15) with 10s expiration
		// - 10.0.0.0 has memory's value (5) with 10s expiration
		if _, found := rateCache.Get("10.0.0.0"); !found {
			t.Error("Entry 10.0.0.0 should not expire until 10 seconds (memory had newer expiration)")
		}

		if _, found := rateCache.Get("192.168.0.0"); !found {
			t.Error("Entry 192.168.0.0 should not expire until 10 seconds (file had newer expiration)")
		}

		// Advance time by 5 more seconds (total 11s)
		time.Sleep(5 * time.Second)
		synctest.Wait()

		// All entries should be expired (verify by trying to get them)
		if _, found := rateCache.Get("192.168.0.0"); found {
			t.Error("Entry 192.168.0.0 should have expired after 10 seconds")
		}
		// Manually trigger cleanup since we're not using automatic janitor
		rateCache.DeleteExpired()
		if rateCache.ItemCount() != 0 {
			t.Errorf("Expected all entries expired, got %d entries", rateCache.ItemCount())
		}
	})
}

// TestSaveAndLoadStateWithExpiration_Synctest tests full save/load cycle with time control
func TestSaveAndLoadStateWithExpiration_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		// Create caches with entries expiring at different times (no cleanup interval to avoid background goroutines)
		rateCache1 := lru.New(1*time.Hour, lru.NoExpiration)
		botCache1 := lru.New(1*time.Hour, lru.NoExpiration)
		verifiedCache1 := lru.New(1*time.Hour, lru.NoExpiration)

		rateCache1.Set("192.168.0.0", uint(10), 5*time.Second)
		rateCache1.Set("10.0.0.0", uint(5), 10*time.Second)
		botCache1.Set("1.2.3.4", true, 3*time.Second)
		verifiedCache1.Set("9.9.9.9", true, lru.NoExpiration)

		// Save state
		_, _, _, _, _, _, err := SaveStateToFile(
			tmpFile,
			false,
			rateCache1,
			botCache1,
			verifiedCache1,
			testLogger(),
		)
		if err != nil {
			t.Fatalf("SaveStateToFile failed: %v", err)
		}

		// Advance time by 4 seconds (bot expires, rates still valid)
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// Load into new caches (no cleanup interval to avoid background goroutines)
		rateCache2 := lru.New(1*time.Hour, lru.NoExpiration)
		botCache2 := lru.New(1*time.Hour, lru.NoExpiration)
		verifiedCache2 := lru.New(1*time.Hour, lru.NoExpiration)

		err = LoadStateFromFile(tmpFile, rateCache2, botCache2, verifiedCache2)
		if err != nil {
			t.Fatalf("LoadStateFromFile failed: %v", err)
		}

		// Bot entry should be filtered out (expired 1 second ago)
		if botCache2.ItemCount() != 0 {
			t.Errorf("Expected 0 bot entries (expired), got %d", botCache2.ItemCount())
		}

		// First rate entry should be loaded (expires at 5s, we're at 4s)
		if _, found := rateCache2.Get("192.168.0.0"); !found {
			t.Error("Rate entry 192.168.0.0 should be loaded (not yet expired)")
		}

		// Second rate entry should be loaded (expires at 10s, we're at 4s)
		if _, found := rateCache2.Get("10.0.0.0"); !found {
			t.Error("Rate entry 10.0.0.0 should be loaded (not yet expired)")
		}

		// Verified entry should be loaded (no expiration)
		if _, found := verifiedCache2.Get("9.9.9.9"); !found {
			t.Error("Verified entry should be loaded (no expiration)")
		}

		// Advance time by 2 more seconds (total 6s, first rate entry expires)
		time.Sleep(2 * time.Second)
		synctest.Wait()

		// First rate entry should be expired
		if _, found := rateCache2.Get("192.168.0.0"); found {
			t.Error("Rate entry 192.168.0.0 should have expired")
		}

		// Second rate entry should still exist
		if _, found := rateCache2.Get("10.0.0.0"); !found {
			t.Error("Rate entry 10.0.0.0 should still be present")
		}
	})
}

// TestReconcilePreservesNewerData_Synctest verifies reconciliation keeps fresher data
func TestReconcilePreservesNewerData_Synctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		tmpFile := t.TempDir() + "/state.json"

		// Create initial state file with data expiring in 5 seconds (no cleanup interval to avoid background goroutines)
		initialCache := lru.New(1*time.Hour, lru.NoExpiration)
		initialCache.Set("192.168.0.0", uint(100), 5*time.Second)

		_, _, _, _, _, _, err := SaveStateToFile(
			tmpFile,
			false,
			initialCache,
			lru.New(1*time.Hour, lru.NoExpiration),
			lru.New(1*time.Hour, lru.NoExpiration),
			testLogger(),
		)
		if err != nil {
			t.Fatalf("Initial save failed: %v", err)
		}

		// Advance time by 2 seconds
		time.Sleep(2 * time.Second)
		synctest.Wait()

		// Create new in-memory data with expiration in 10 seconds from original start
		// This represents fresher data (no cleanup interval to avoid background goroutines)
		newCache := lru.New(1*time.Hour, lru.NoExpiration)
		newCache.Set("192.168.0.0", uint(200), 8*time.Second) // expires at start+10s

		// Save with reconciliation enabled
		_, _, _, _, _, _, err = SaveStateToFile(
			tmpFile,
			true, // reconcile
			newCache,
			lru.New(1*time.Hour, lru.NoExpiration),
			lru.New(1*time.Hour, lru.NoExpiration),
			testLogger(),
		)
		if err != nil {
			t.Fatalf("Reconciled save failed: %v", err)
		}

		// Load back and verify we got the newer value (no cleanup interval to avoid background goroutines)
		loadedCache := lru.New(1*time.Hour, lru.NoExpiration)
		err = LoadStateFromFile(
			tmpFile,
			loadedCache,
			lru.New(1*time.Hour, lru.NoExpiration),
			lru.New(1*time.Hour, lru.NoExpiration),
		)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		// Should have the newer value (200 with later expiration)
		if v, found := loadedCache.Get("192.168.0.0"); !found || v.(uint) != 200 {
			t.Errorf("Expected value 200 (newer data), got %v (found=%v)", v, found)
		}

		// Advance time by 4 more seconds (total 6s from start)
		// Old data would have expired at 5s, new data expires at 10s
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// New data should still be valid
		if _, found := loadedCache.Get("192.168.0.0"); !found {
			t.Error("Newer data should still be valid (expires at 10s, we're at 6s)")
		}

		// Advance time by 5 more seconds (total 11s from start)
		time.Sleep(5 * time.Second)
		synctest.Wait()

		// Now the newer data should also be expired
		if _, found := loadedCache.Get("192.168.0.0"); found {
			t.Error("Newer data should have expired after 10 seconds")
		}
	})
}

// TestCacheCleanupInterval_Synctest verifies go-cache cleanup runs on schedule
// NOTE: This test is skipped because it tests the janitor goroutine which is incompatible with synctest
func TestCacheCleanupInterval_Synctest(t *testing.T) {
	t.Skip("Skipping test that requires janitor goroutine (incompatible with synctest)")
	synctest.Test(t, func(t *testing.T) {
		// Create cache with 1 minute cleanup interval
		cleanupInterval := 1 * time.Minute
		cache := lru.New(5*time.Second, cleanupInterval)

		// Add entry that expires in 3 seconds
		cache.Set("test-key", uint(42), 3*time.Second)

		// Verify entry exists
		if _, found := cache.Get("test-key"); !found {
			t.Fatal("Entry should exist immediately after Set")
		}

		// Advance time by 4 seconds (entry expired but cleanup hasn't run)
		time.Sleep(4 * time.Second)
		synctest.Wait()

		// Entry is expired but might still be in cache (cleanup hasn't run yet)
		// The Get should return false because go-cache checks expiration on Get
		if _, found := cache.Get("test-key"); found {
			t.Error("Entry should be expired after 3 seconds")
		}

		// Advance time to trigger cleanup (cleanup runs every 1 minute)
		time.Sleep(57 * time.Second) // Total 61 seconds, cleanup should have run
		synctest.Wait()

		// Entry should definitely be cleaned up now
		if cache.ItemCount() != 0 {
			t.Errorf("Cache should be empty after cleanup, got %d items", cache.ItemCount())
		}
	})
}
