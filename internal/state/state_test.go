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
	if state.Rate["192.168.0.0"] != 10 {
		t.Errorf("Expected rate 10 for 192.168.0.0, got %d", state.Rate["192.168.0.0"])
	}
	if state.Rate["10.0.0.0"] != 5 {
		t.Errorf("Expected rate 5 for 10.0.0.0, got %d", state.Rate["10.0.0.0"])
	}

	// Verify bot cache data
	if len(state.Bots) != 2 {
		t.Errorf("Expected 2 bot entries, got %d", len(state.Bots))
	}
	if state.Bots["1.2.3.4"] != true {
		t.Error("Expected bot 1.2.3.4 to be true")
	}
	if state.Bots["5.6.7.8"] != false {
		t.Error("Expected bot 5.6.7.8 to be false")
	}

	// Verify verified cache data
	if len(state.Verified) != 1 {
		t.Errorf("Expected 1 verified entry, got %d", len(state.Verified))
	}
	if state.Verified["9.9.9.9"] != true {
		t.Error("Expected 9.9.9.9 to be verified")
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
