package state

import (
	"encoding/json"
	"log/slog"
	"os"
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
		if fileEntry.Expiration > 0 && fileEntry.Expiration <= now {
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

// SaveStateToFile saves state to a file with locking and optional reconciliation.
// When reconcile is true, it reads and merges existing file state before saving.
// Returns timing metrics for debugging.
func SaveStateToFile(
	filePath string,
	reconcile bool,
	rateCache, botCache, verifiedCache *lru.Cache,
	log *slog.Logger,
) (lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs int64, err error) {
	startTime := time.Now()

	lock, err := NewFileLock(filePath + ".lock")
	if err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	defer lock.Close()

	if err := lock.Lock(); err != nil {
		return 0, 0, 0, 0, 0, 0, err
	}
	lockDuration := time.Since(startTime)

	var readDuration, reconcileDuration, marshalDuration, writeDuration time.Duration

	// Reconcile with existing file state if enabled
	if reconcile {
		readStart := time.Now()
		fileContent, readErr := os.ReadFile(filePath)
		readDuration = time.Since(readStart)

		if readErr == nil && len(fileContent) > 0 {
			reconcileStart := time.Now()
			var fileState State
			if unmarshalErr := json.Unmarshal(fileContent, &fileState); unmarshalErr == nil {
				log.Debug("Reconciling state before save", "fileBytes", len(fileContent))
				ReconcileState(fileState, rateCache, botCache, verifiedCache)
			}
			reconcileDuration = time.Since(reconcileStart)
		}
	}

	// Marshal current state
	marshalStart := time.Now()
	currentState := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())
	jsonData, err := json.Marshal(currentState)
	marshalDuration = time.Since(marshalStart)

	if err != nil {
		return lockDuration.Milliseconds(), readDuration.Milliseconds(),
			reconcileDuration.Milliseconds(), marshalDuration.Milliseconds(),
			0, 0, err
	}

	// Write to disk
	writeStart := time.Now()
	err = os.WriteFile(filePath, jsonData, 0644)
	writeDuration = time.Since(writeStart)

	if err != nil {
		return lockDuration.Milliseconds(), readDuration.Milliseconds(),
			reconcileDuration.Milliseconds(), marshalDuration.Milliseconds(),
			writeDuration.Milliseconds(), 0, err
	}

	totalDuration := time.Since(startTime)
	return lockDuration.Milliseconds(), readDuration.Milliseconds(),
		reconcileDuration.Milliseconds(), marshalDuration.Milliseconds(),
		writeDuration.Milliseconds(), totalDuration.Milliseconds(), nil
}

// LoadStateFromFile loads state from a file with locking.
func LoadStateFromFile(
	filePath string,
	rateCache, botCache, verifiedCache *lru.Cache,
) error {
	lock, err := NewFileLock(filePath + ".lock")
	if err != nil {
		return err
	}
	defer lock.Close()

	if err := lock.Lock(); err != nil {
		return err
	}

	fileContent, err := os.ReadFile(filePath)
	if err != nil || len(fileContent) == 0 {
		return err
	}

	var loadedState State
	err = json.Unmarshal(fileContent, &loadedState)
	if err != nil {
		return err
	}

	// Use SetState which properly handles expiration times
	SetState(loadedState, rateCache, botCache, verifiedCache)

	return nil
}
