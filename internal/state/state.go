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
	"unicode/utf8"

	lru "github.com/patrickmn/go-cache"
)

// CacheEntry represents a cache item with its expiration time
type CacheEntry struct {
	Value      interface{} `json:"value"`
	Expiration int64       `json:"expiration"` // Unix timestamp in nanoseconds, 0 means no expiration
}

// State contains the persisted cache snapshot and approximate cache memory usage.
type State struct {
	Verified map[string]CacheEntry `json:"verified"`
	Memory   map[string]uintptr    `json:"memory"`
}

// Keep concrete entry types: Traefik's Yaegi interpreter cannot reliably handle
// generic persistentEntry[T] map fields.
type persistentBoolEntry struct {
	Value      bool  `json:"value"`
	Expiration int64 `json:"expiration"`
}

type persistentState struct {
	Verified map[string]persistentBoolEntry `json:"verified"`
	Memory   map[string]uintptr             `json:"memory"`
}

// SaveMetrics reports timing and entry counts for a state save.
type SaveMetrics struct {
	LockMs          int64
	MarshalMs       int64
	WriteMs         int64
	TotalMs         int64
	VerifiedEntries int
}

// GetState converts cache items into a serializable state snapshot.
func GetState(verifiedCache map[string]lru.Item) State {
	state := State{
		Memory: make(map[string]uintptr, 1),
	}

	state.Verified, state.Memory["verified"] = getCacheEntries[bool](verifiedCache)

	return state
}

// SetState loads state data into the provided caches, preserving expiration times.
// If an entry has already expired (expiration < now), it will be skipped.
func SetState(state State, verifiedCache *lru.Cache) {
	loadCacheEntries(state.Verified, verifiedCache, convertBoolValue)
}

// SaveStateToFileWithMetrics saves verified state to a file with locking.
func SaveStateToFileWithMetrics(
	filePath string,
	verifiedCache *lru.Cache,
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
	log.Debug("Saving state snapshot")

	verifiedItems := verifiedCache.Items()
	metrics.VerifiedEntries = len(verifiedItems)

	metrics.MarshalMs, metrics.WriteMs, err = atomicWriteStateFile(filePath, verifiedItems, 0600)
	if err != nil {
		return metrics, err
	}

	metrics.TotalMs = time.Since(startTime).Milliseconds()
	return metrics, nil
}

func atomicWriteStateFile(
	filePath string,
	verifiedItems map[string]lru.Item,
	perm os.FileMode,
) (marshalMs, writeMs int64, err error) {
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, filepath.Base(filePath)+".tmp-*")
	if err != nil {
		return 0, 0, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	writer := bufio.NewWriterSize(tmp, 1024*1024)
	marshalStart := time.Now()
	if err := writeStateJSON(writer, verifiedItems); err != nil {
		_ = tmp.Close()
		return 0, 0, err
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return 0, 0, err
	}
	marshalMs = time.Since(marshalStart).Milliseconds()

	writeStart := time.Now()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return marshalMs, 0, err
	}
	if err := tmp.Close(); err != nil {
		return marshalMs, 0, err
	}

	if err := os.Rename(tmpName, filePath); err != nil {
		return marshalMs, 0, err
	}
	return marshalMs, time.Since(writeStart).Milliseconds(), nil
}

func writeStateJSON(
	writer *bufio.Writer,
	verifiedItems map[string]lru.Item,
) error {
	if err := writeString(writer, `{"verified":`); err != nil {
		return err
	}
	verifiedMemory, err := writeCacheEntryMap[bool](writer, verifiedItems, writeBool)
	if err != nil {
		return err
	}

	if err := writeString(writer, `,"memory":{"verified":`); err != nil {
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

	memoryUsage := cacheEntryMapSize
	first := true
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

		if err := writeJSONString(writer, key); err != nil {
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

		memoryUsage += stringSize
		memoryUsage += lruItemSize
		memoryUsage += uintptr(len(key))
	}

	if err := writer.WriteByte('}'); err != nil {
		return memoryUsage, err
	}
	return memoryUsage, nil
}

var (
	cacheEntryMapSize = reflect.TypeOf(map[string]CacheEntry{}).Size()
	stringSize        = reflect.TypeOf("").Size()
	lruItemSize       = reflect.TypeOf(lru.Item{}).Size()
)

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

func writeJSONString(writer *bufio.Writer, value string) error {
	if isPlainJSONString(value) {
		if err := writer.WriteByte('"'); err != nil {
			return err
		}
		if err := writeString(writer, value); err != nil {
			return err
		}
		return writer.WriteByte('"')
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}

func isPlainJSONString(value string) bool {
	asciiOnly := true
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\', '"':
			return false
		default:
			if value[i] < 0x20 {
				return false
			}
			if value[i] >= utf8.RuneSelf {
				asciiOnly = false
			}
		}
	}
	return asciiOnly || utf8.ValidString(value)
}

// LoadStateFromFile loads state from a file with locking.
func LoadStateFromFile(
	filePath string,
	verifiedCache *lru.Cache,
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

	setPersistentState(loadedState, verifiedCache)

	return nil
}

func calculateDuration(expiration int64, now int64) time.Duration {
	if expiration == 0 {
		return lru.NoExpiration
	}
	return time.Duration(expiration - now)
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

func setPersistentState(state persistentState, verifiedCache *lru.Cache) {
	loadPersistentBoolEntries(state.Verified, verifiedCache)
}

func loadPersistentBoolEntries(entries map[string]persistentBoolEntry, cache *lru.Cache) {
	now := time.Now().UnixNano()
	for key, entry := range entries {
		if entry.Expiration > 0 && entry.Expiration <= now {
			continue
		}
		cache.Set(key, entry.Value, calculateDuration(entry.Expiration, now))
	}
}
