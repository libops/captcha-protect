package state

import (
	"encoding/json"
	"fmt"
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

	state.Rate, state.Memory["rate"] = getCacheEntries[uint](rateCache)
	state.Bots, state.Memory["bot"] = getCacheEntries[bool](botCache)
	state.Verified, state.Memory["verified"] = getCacheEntries[bool](verifiedCache)

	return state
}

// SetState loads state data into the provided caches, preserving expiration times.
// If an entry has already expired (expiration < now), it will be skipped.
func SetState(state State, rateCache, botCache, verifiedCache *lru.Cache) {
	loadCacheEntries(state.Rate, rateCache, convertRateValue)
	loadCacheEntries(state.Bots, botCache, convertBoolValue)
	loadCacheEntries(state.Verified, verifiedCache, convertBoolValue)
}

// ReconcileState merges file-based state with in-memory state.
func ReconcileState(fileState State, rateCache, botCache, verifiedCache *lru.Cache) {
	rateItems := rateCache.Items()
	botItems := botCache.Items()
	verifiedItems := verifiedCache.Items()

	// Use "max value wins" for rate cache
	reconcileRateCache(fileState.Rate, rateItems, rateCache, convertRateValue)

	// Use "later expiration wins" for bot and verified caches
	reconcileCacheEntries(fileState.Bots, botItems, botCache, convertBoolValue)
	reconcileCacheEntries(fileState.Verified, verifiedItems, verifiedCache, convertBoolValue)
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
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("failed to create lock: %w", err)
	}
	defer lock.Close()

	if err := lock.Lock(); err != nil {
		return 0, 0, 0, 0, 0, 0, fmt.Errorf("failed to acquire lock: %w", err)
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

func calculateDuration(expiration int64, now int64) time.Duration {
	if expiration == 0 {
		return lru.NoExpiration
	}
	return time.Duration(expiration - now)
}

func convertRateValue(v interface{}) (uint, bool) {
	switch val := v.(type) {
	case uint:
		return val, true
	case float64:
		return uint(val), true
	case int:
		return uint(val), true
	default:
		return 0, false
	}
}

func convertBoolValue(v interface{}) (bool, bool) {
	switch val := v.(type) {
	case bool:
		return val, true
	default:
		return false, false
	}
}

func getCacheEntries[T any](items map[string]lru.Item) (map[string]CacheEntry, uintptr) {
	entries := make(map[string]CacheEntry, len(items))
	var memoryUsage uintptr
	memoryUsage = reflect.TypeOf(entries).Size()

	for k, v := range items {
		entries[k] = CacheEntry{
			Value:      v.Object.(T),
			Expiration: v.Expiration,
		}
		memoryUsage += reflect.TypeOf(k).Size()
		memoryUsage += reflect.TypeOf(v).Size()
		memoryUsage += uintptr(len(k))
	}
	return entries, memoryUsage
}

func loadCacheEntries[T any](
	entries map[string]CacheEntry,
	cache *lru.Cache,
	converter func(interface{}) (T, bool),
) {
	now := time.Now().UnixNano()
	for k, entry := range entries {
		if entry.Expiration > 0 && entry.Expiration <= now {
			continue
		}
		value, ok := converter(entry.Value)
		if !ok {
			continue
		}
		duration := calculateDuration(entry.Expiration, now)
		cache.Set(k, value, duration)
	}
}

// reconcileCacheEntries implements "later expiration wins"
// This is correct for bool flags (Verified, Bots).
func reconcileCacheEntries[T any](
	fileEntries map[string]CacheEntry,
	memItems map[string]lru.Item,
	cache *lru.Cache,
	converter func(interface{}) (T, bool),
) {
	now := time.Now().UnixNano()
	for k, fileEntry := range fileEntries {
		if fileEntry.Expiration > 0 && fileEntry.Expiration <= now {
			continue
		}

		value, ok := converter(fileEntry.Value)
		if !ok {
			continue
		}

		duration := calculateDuration(fileEntry.Expiration, now)

		memItem, exists := memItems[k]
		if !exists {
			cache.Set(k, value, duration)
			continue
		}

		if fileEntry.Expiration > memItem.Expiration {
			cache.Set(k, value, duration)
		}
	}
}

// reconcileRateCache implements "max value wins" and "max expiration wins".
// This prevents runaway growth (from summing) and accepts data loss
// (under-counting) as the safer alternative.
func reconcileRateCache(
	fileEntries map[string]CacheEntry,
	memItems map[string]lru.Item,
	cache *lru.Cache,
	converter func(interface{}) (uint, bool),
) {
	now := time.Now().UnixNano()
	for k, fileEntry := range fileEntries {
		if fileEntry.Expiration > 0 && fileEntry.Expiration <= now {
			continue
		}

		fileValue, ok := converter(fileEntry.Value)
		if !ok {
			continue
		}

		memItem, exists := memItems[k]
		if !exists {
			// Entry only in file, just add it
			duration := calculateDuration(fileEntry.Expiration, now)
			cache.Set(k, fileValue, duration)
			continue
		}

		// Entry in both, combine them
		memValue, ok := memItem.Object.(uint)
		if !ok {
			// In-memory object is not uint, something is wrong.
			// Overwrite with file value as a fallback.
			duration := calculateDuration(fileEntry.Expiration, now)
			cache.Set(k, fileValue, duration)
			continue
		}

		// Use the HIGHEST value, not the sum
		combinedValue := maxUint(fileValue, memValue)
		// Use the LATER expiration
		laterExpiration := max(fileEntry.Expiration, memItem.Expiration)

		duration := calculateDuration(laterExpiration, now)
		cache.Set(k, combinedValue, duration)
	}
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxUint(a, b uint) uint {
	if a > b {
		return a
	}
	return b
}
