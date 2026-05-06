package state

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

type SaveMetrics struct {
	LockMs          int64
	ReadMs          int64
	ReconcileMs     int64
	MarshalMs       int64
	WriteMs         int64
	TotalMs         int64
	RateEntries     int
	BotEntries      int
	VerifiedEntries int
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
	metrics, err := SaveStateToFileWithMetrics(filePath, reconcile, rateCache, botCache, verifiedCache, log)
	return metrics.LockMs, metrics.ReadMs, metrics.ReconcileMs, metrics.MarshalMs, metrics.WriteMs, metrics.TotalMs, err
}

func SaveStateToFileWithMetrics(
	filePath string,
	reconcile bool,
	rateCache, botCache, verifiedCache *lru.Cache,
	log *slog.Logger,
) (SaveMetrics, error) {
	startTime := time.Now()
	metrics := SaveMetrics{}

	lock, err := NewFileLock(filePath + ".lock")
	if err != nil {
		return metrics, fmt.Errorf("failed to create lock: %w", err)
	}
	defer lock.Close()

	if err := lock.Lock(); err != nil {
		return metrics, fmt.Errorf("failed to acquire lock: %w", err)
	}
	metrics.LockMs = time.Since(startTime).Milliseconds()

	// Reconcile with existing file state if enabled
	if reconcile {
		readStart := time.Now()
		fileContent, readErr := os.ReadFile(filePath)
		metrics.ReadMs = time.Since(readStart).Milliseconds()

		if readErr == nil && len(fileContent) > 0 {
			reconcileStart := time.Now()
			var fileState State
			if unmarshalErr := json.Unmarshal(fileContent, &fileState); unmarshalErr == nil {
				log.Debug("Reconciling state before save", "fileBytes", len(fileContent))
				ReconcileState(fileState, rateCache, botCache, verifiedCache)
			}
			metrics.ReconcileMs = time.Since(reconcileStart).Milliseconds()
		}
	}

	// Marshal current state
	marshalStart := time.Now()
	currentState := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())
	jsonData, err := json.Marshal(currentState)
	metrics.MarshalMs = time.Since(marshalStart).Milliseconds()
	metrics.RateEntries = len(currentState.Rate)
	metrics.BotEntries = len(currentState.Bots)
	metrics.VerifiedEntries = len(currentState.Verified)

	if err != nil {
		return metrics, err
	}

	// Write to disk
	writeStart := time.Now()
	err = atomicWriteFile(filePath, jsonData, 0644)
	metrics.WriteMs = time.Since(writeStart).Milliseconds()

	if err != nil {
		return metrics, err
	}

	metrics.TotalMs = time.Since(startTime).Milliseconds()
	return metrics, nil
}

func atomicWriteFile(filePath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, filePath)
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

func ReconcileStateFromFile(
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

	var fileState State
	if err := json.Unmarshal(fileContent, &fileState); err != nil {
		return err
	}

	ReconcileState(fileState, rateCache, botCache, verifiedCache)
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
