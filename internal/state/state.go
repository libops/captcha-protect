package state

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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

type persistentEntry[T any] struct {
	Value      T     `json:"value"`
	Expiration int64 `json:"expiration"`
}

type persistentState struct {
	Rate     map[string]persistentEntry[uint] `json:"rate"`
	Bots     map[string]persistentEntry[bool] `json:"bots"`
	Verified map[string]persistentEntry[bool] `json:"verified"`
	Memory   map[string]uintptr               `json:"memory"`
}

type ignoredJSON struct{}

func (ignoredJSON) UnmarshalJSON(_ []byte) error {
	return nil
}

type reconcileStateFile struct {
	Rate     map[string]persistentEntry[uint] `json:"rate"`
	Bots     ignoredJSON                      `json:"bots"` // Bot cache is derived and too large to merge on every state save.
	Verified map[string]persistentEntry[bool] `json:"verified"`
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
		fileContent, readErr := os.ReadFile(filePath) // #nosec G304 -- persistent state path is trusted middleware configuration.
		metrics.ReadMs = time.Since(readStart).Milliseconds()

		if readErr == nil && len(fileContent) > 0 {
			reconcileStart := time.Now()
			var fileState reconcileStateFile
			if unmarshalErr := json.Unmarshal(fileContent, &fileState); unmarshalErr == nil {
				log.Debug("Reconciling state before save", "fileBytes", len(fileContent))
				reconcilePersistentFileState(fileState, rateCache, verifiedCache)
			}
			metrics.ReconcileMs = time.Since(reconcileStart).Milliseconds()
		}
	}

	// Bot cache entries are derived from DNS/IP checks and can dwarf the
	// state that needs cross-instance sharing. Persist only rate limiter and
	// verified-user state; existing files with bot entries still load.
	rateItems := rateCache.Items()
	verifiedItems := verifiedCache.Items()
	metrics.RateEntries = len(rateItems)
	metrics.BotEntries = 0
	metrics.VerifiedEntries = len(verifiedItems)

	marshalStart := time.Now()
	err = atomicWriteStateFile(filePath, rateItems, nil, verifiedItems, 0600)
	metrics.MarshalMs = time.Since(marshalStart).Milliseconds()

	if err != nil {
		return metrics, err
	}

	metrics.TotalMs = time.Since(startTime).Milliseconds()
	return metrics, nil
}

func atomicWriteStateFile(
	filePath string,
	rateItems, botItems, verifiedItems map[string]lru.Item,
	perm os.FileMode,
) error {
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	writer := bufio.NewWriterSize(tmp, 1024*1024)
	if err := writeStateJSON(writer, rateItems, botItems, verifiedItems); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
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

func writeStateJSON(
	writer *bufio.Writer,
	rateItems, botItems, verifiedItems map[string]lru.Item,
) error {
	if err := writeString(writer, `{"rate":`); err != nil {
		return err
	}
	rateMemory, err := writeCacheEntryMap[uint](writer, rateItems, writeUint)
	if err != nil {
		return err
	}
	if err := writeString(writer, `,"bots":`); err != nil {
		return err
	}
	botMemory, err := writeCacheEntryMap[bool](writer, botItems, writeBool)
	if err != nil {
		return err
	}
	if err := writeString(writer, `,"verified":`); err != nil {
		return err
	}
	verifiedMemory, err := writeCacheEntryMap[bool](writer, verifiedItems, writeBool)
	if err != nil {
		return err
	}

	if err := writeString(writer, `,"memory":{"rate":`); err != nil {
		return err
	}
	if err := writeString(writer, strconv.FormatUint(uint64(rateMemory), 10)); err != nil {
		return err
	}
	if err := writeString(writer, `,"bot":`); err != nil {
		return err
	}
	if err := writeString(writer, strconv.FormatUint(uint64(botMemory), 10)); err != nil {
		return err
	}
	if err := writeString(writer, `,"verified":`); err != nil {
		return err
	}
	if err := writeString(writer, strconv.FormatUint(uint64(verifiedMemory), 10)); err != nil {
		return err
	}
	return writeString(writer, `}}`)
}

func writeCacheEntryMap[T any](
	writer *bufio.Writer,
	items map[string]lru.Item,
	writeValue func(*bufio.Writer, T) error,
) (uintptr, error) {
	if err := writer.WriteByte('{'); err != nil {
		return 0, err
	}

	memoryUsage := reflect.TypeOf(map[string]CacheEntry{}).Size()
	first := true
	quotedKey := make([]byte, 0, 64)
	for key, item := range items {
		value, ok := item.Object.(T)
		if !ok {
			return memoryUsage, fmt.Errorf("unexpected cache value type for %q", key)
		}

		if !first {
			if err := writer.WriteByte(','); err != nil {
				return memoryUsage, err
			}
		}
		first = false

		quotedKey = strconv.AppendQuote(quotedKey[:0], key)
		if _, err := writer.Write(quotedKey); err != nil {
			return memoryUsage, err
		}
		if err := writeString(writer, `:{"value":`); err != nil {
			return memoryUsage, err
		}
		if err := writeValue(writer, value); err != nil {
			return memoryUsage, err
		}
		if err := writeString(writer, `,"expiration":`); err != nil {
			return memoryUsage, err
		}
		if err := writeString(writer, strconv.FormatInt(item.Expiration, 10)); err != nil {
			return memoryUsage, err
		}
		if err := writer.WriteByte('}'); err != nil {
			return memoryUsage, err
		}

		memoryUsage += reflect.TypeOf(key).Size()
		memoryUsage += reflect.TypeOf(item).Size()
		memoryUsage += uintptr(len(key))
	}

	if err := writer.WriteByte('}'); err != nil {
		return memoryUsage, err
	}
	return memoryUsage, nil
}

func writeUint(writer *bufio.Writer, value uint) error {
	return writeString(writer, strconv.FormatUint(uint64(value), 10))
}

func writeBool(writer *bufio.Writer, value bool) error {
	if value {
		return writeString(writer, "true")
	}
	return writeString(writer, "false")
}

func writeString(writer *bufio.Writer, value string) error {
	_, err := writer.WriteString(value)
	return err
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

	fileContent, err := os.ReadFile(filePath) // #nosec G304 -- persistent state path is trusted middleware configuration.
	if err != nil || len(fileContent) == 0 {
		return err
	}

	var loadedState persistentState
	err = json.Unmarshal(fileContent, &loadedState)
	if err != nil {
		return err
	}

	// Use SetState which properly handles expiration times
	setPersistentState(loadedState, rateCache, botCache, verifiedCache)

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

	fileContent, err := os.ReadFile(filePath) // #nosec G304 -- persistent state path is trusted middleware configuration.
	if err != nil || len(fileContent) == 0 {
		return err
	}

	var fileState reconcileStateFile
	if err := json.Unmarshal(fileContent, &fileState); err != nil {
		return err
	}

	reconcilePersistentFileState(fileState, rateCache, verifiedCache)
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

func setPersistentState(state persistentState, rateCache, botCache, verifiedCache *lru.Cache) {
	loadPersistentEntries(state.Rate, rateCache)
	loadPersistentEntries(state.Bots, botCache)
	loadPersistentEntries(state.Verified, verifiedCache)
}

func loadPersistentEntries[T any](entries map[string]persistentEntry[T], cache *lru.Cache) {
	now := time.Now().UnixNano()
	for key, entry := range entries {
		if entry.Expiration > 0 && entry.Expiration <= now {
			continue
		}
		cache.Set(key, entry.Value, calculateDuration(entry.Expiration, now))
	}
}

func reconcilePersistentFileState(state reconcileStateFile, rateCache, verifiedCache *lru.Cache) {
	rateItems := rateCache.Items()
	verifiedItems := verifiedCache.Items()

	reconcilePersistentRateCache(state.Rate, rateItems, rateCache)
	reconcilePersistentCacheEntries(state.Verified, verifiedItems, verifiedCache)
}

func reconcilePersistentCacheEntries[T any](
	fileEntries map[string]persistentEntry[T],
	memItems map[string]lru.Item,
	cache *lru.Cache,
) {
	now := time.Now().UnixNano()
	for key, fileEntry := range fileEntries {
		if fileEntry.Expiration > 0 && fileEntry.Expiration <= now {
			continue
		}

		duration := calculateDuration(fileEntry.Expiration, now)
		memItem, exists := memItems[key]
		if !exists {
			cache.Set(key, fileEntry.Value, duration)
			continue
		}

		if fileEntry.Expiration > memItem.Expiration {
			cache.Set(key, fileEntry.Value, duration)
		}
	}
}

func reconcilePersistentRateCache(
	fileEntries map[string]persistentEntry[uint],
	memItems map[string]lru.Item,
	cache *lru.Cache,
) {
	now := time.Now().UnixNano()
	for key, fileEntry := range fileEntries {
		if fileEntry.Expiration > 0 && fileEntry.Expiration <= now {
			continue
		}

		memItem, exists := memItems[key]
		if !exists {
			cache.Set(key, fileEntry.Value, calculateDuration(fileEntry.Expiration, now))
			continue
		}

		memValue, ok := memItem.Object.(uint)
		if !ok {
			cache.Set(key, fileEntry.Value, calculateDuration(fileEntry.Expiration, now))
			continue
		}

		combinedValue := maxUint(fileEntry.Value, memValue)
		laterExpiration := max(fileEntry.Expiration, memItem.Expiration)
		cache.Set(key, combinedValue, calculateDuration(laterExpiration, now))
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
