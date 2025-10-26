package state

import (
	"reflect"
	"time"

	lru "github.com/patrickmn/go-cache"
)

// CacheEntry represents a cache item with its expiration time
type CacheEntry struct {
	Value      interface{} `json:"value"`
	Expiration int64       `json:"expiration"` // Unix timestamp in nanoseconds, 0 means no expiration
}

type State struct {
	Rate     map[string]CacheEntry `json:"rate"`
	Bots     map[string]CacheEntry `json:"bots"`
	Verified map[string]CacheEntry `json:"verified"`
	Memory   map[string]uintptr    `json:"memory"`
}

func GetState(rateCache, botCache, verifiedCache map[string]lru.Item) State {
	state := State{
		Memory: make(map[string]uintptr, 3),
	}

	state.Rate = make(map[string]CacheEntry, len(rateCache))
	state.Memory["rate"] = reflect.TypeOf(state.Rate).Size()
	for k, v := range rateCache {
		state.Rate[k] = CacheEntry{
			Value:      v.Object.(uint),
			Expiration: v.Expiration,
		}
		state.Memory["rate"] += reflect.TypeOf(k).Size()
		state.Memory["rate"] += reflect.TypeOf(v).Size()
		state.Memory["rate"] += uintptr(len(k))
	}

	state.Bots = make(map[string]CacheEntry, len(botCache))
	state.Memory["bot"] = reflect.TypeOf(state.Bots).Size()
	for k, v := range botCache {
		state.Bots[k] = CacheEntry{
			Value:      v.Object.(bool),
			Expiration: v.Expiration,
		}
		state.Memory["bot"] += reflect.TypeOf(k).Size()
		state.Memory["bot"] += reflect.TypeOf(v).Size()
		state.Memory["bot"] += uintptr(len(k))
	}

	state.Verified = make(map[string]CacheEntry, len(verifiedCache))
	state.Memory["verified"] = reflect.TypeOf(state.Verified).Size()
	for k, v := range verifiedCache {
		state.Verified[k] = CacheEntry{
			Value:      v.Object.(bool),
			Expiration: v.Expiration,
		}
		state.Memory["verified"] += reflect.TypeOf(k).Size()
		state.Memory["verified"] += reflect.TypeOf(v).Size()
		state.Memory["verified"] += uintptr(len(k))
	}

	return state
}

// SetState loads state data into the provided caches, preserving expiration times.
// If an entry has already expired (expiration < now), it will be skipped.
func SetState(state State, rateCache, botCache, verifiedCache *lru.Cache) {
	now := time.Now().UnixNano()

	for k, entry := range state.Rate {
		if entry.Expiration > 0 && entry.Expiration < now {
			continue // Skip expired entries
		}
		duration := time.Duration(entry.Expiration - now)
		if entry.Expiration == 0 {
			duration = lru.NoExpiration
		}

		// Handle JSON unmarshaling where numbers become float64
		var value uint
		switch v := entry.Value.(type) {
		case uint:
			value = v
		case float64:
			value = uint(v)
		case int:
			value = uint(v)
		default:
			// Skip invalid types
			continue
		}
		rateCache.Set(k, value, duration)
	}

	for k, entry := range state.Bots {
		if entry.Expiration > 0 && entry.Expiration < now {
			continue
		}
		duration := time.Duration(entry.Expiration - now)
		if entry.Expiration == 0 {
			duration = lru.NoExpiration
		}

		// Handle JSON unmarshaling
		var value bool
		switch v := entry.Value.(type) {
		case bool:
			value = v
		default:
			continue
		}
		botCache.Set(k, value, duration)
	}

	for k, entry := range state.Verified {
		if entry.Expiration > 0 && entry.Expiration < now {
			continue
		}
		duration := time.Duration(entry.Expiration - now)
		if entry.Expiration == 0 {
			duration = lru.NoExpiration
		}

		// Handle JSON unmarshaling
		var value bool
		switch v := entry.Value.(type) {
		case bool:
			value = v
		default:
			continue
		}
		verifiedCache.Set(k, value, duration)
	}
}

// ReconcileState merges file-based state with in-memory state.
// For each cache type, it keeps the entry with the later expiration time.
// This prevents multiple plugin instances from overwriting each other's fresh data.
func ReconcileState(fileState State, rateCache, botCache, verifiedCache *lru.Cache) {
	now := time.Now().UnixNano()

	// Get all in-memory items with their expiration times
	rateItems := rateCache.Items()
	botItems := botCache.Items()
	verifiedItems := verifiedCache.Items()

	// Reconcile rate cache
	for k, fileEntry := range fileState.Rate {
		if fileEntry.Expiration > 0 && fileEntry.Expiration < now {
			continue // Skip expired entries
		}

		// Handle JSON unmarshaling where numbers become float64
		var value uint
		switch v := fileEntry.Value.(type) {
		case uint:
			value = v
		case float64:
			value = uint(v)
		case int:
			value = uint(v)
		default:
			// Skip invalid types
			continue
		}

		memItem, exists := rateItems[k]
		if !exists {
			// Entry only exists in file, add it
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			rateCache.Set(k, value, duration)
			continue
		}

		// Both exist - keep the one with later expiration (more recent data)
		if fileEntry.Expiration > memItem.Expiration {
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			rateCache.Set(k, value, duration)
		}
	}

	// Reconcile bot cache
	for k, fileEntry := range fileState.Bots {
		if fileEntry.Expiration > 0 && fileEntry.Expiration < now {
			continue
		}

		// Handle JSON unmarshaling
		var value bool
		switch v := fileEntry.Value.(type) {
		case bool:
			value = v
		default:
			continue
		}

		memItem, exists := botItems[k]
		if !exists {
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			botCache.Set(k, value, duration)
			continue
		}

		if fileEntry.Expiration > memItem.Expiration {
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			botCache.Set(k, value, duration)
		}
	}

	// Reconcile verified cache (MOST CRITICAL - don't lose successful CAPTCHA verifications)
	for k, fileEntry := range fileState.Verified {
		if fileEntry.Expiration > 0 && fileEntry.Expiration < now {
			continue
		}

		// Handle JSON unmarshaling
		var value bool
		switch v := fileEntry.Value.(type) {
		case bool:
			value = v
		default:
			continue
		}

		memItem, exists := verifiedItems[k]
		if !exists {
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			verifiedCache.Set(k, value, duration)
			continue
		}

		if fileEntry.Expiration > memItem.Expiration {
			duration := time.Duration(fileEntry.Expiration - now)
			if fileEntry.Expiration == 0 {
				duration = lru.NoExpiration
			}
			verifiedCache.Set(k, value, duration)
		}
	}
}
