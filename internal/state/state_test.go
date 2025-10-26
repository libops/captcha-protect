package state

import (
	"testing"
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
