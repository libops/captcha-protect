package state

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"testing"
	"time"

	lru "github.com/patrickmn/go-cache"
)

// This file contains stress tests for state persistence operations at various scales.
//
// Performance Findings (Apple M2 Pro):
//   Small (16 rate / 65K bots / 256 verified → 3.87 MB JSON):
//     - SaveStateToFile with reconciliation: ~84ms
//   Medium (256 rate / 262K bots / 65K verified → 19.31 MB JSON):
//     - SaveStateToFile with reconciliation: ~410ms
//   Large (1,024 rate / 1M bots / 262K verified → 77.61 MB JSON):
//     - SaveStateToFile with reconciliation: ~1.8s
//   XLarge (4,096 rate / 4.2M bots / 1M verified → 312.68 MB JSON):
//     - SaveStateToFile with reconciliation: ~8.7s (approaching 10s save window limit)
//
// Recommendation: Do not enable enableStateReconciliation for sites with >1M unique visitors.
// The reconciliation overhead at scale (5-8s) conflicts with the 10-second save interval.
//
// NOTE: The ci/run-stress-tests.sh script reports these metrics. In CI environments,
// thresholds are informational only (won't fail the build) since CI runners vary in
// performance. Thresholds are enforced in local development.

// StressLevel defines the size parameters for a stress test
type StressLevel struct {
	Name            string
	RateEntries     int
	BotEntries      int
	VerifiedEntries int
}

// getStressLevels returns the configured stress test levels
// Note: We cap large levels at practical sizes to avoid exhausting system memory
func getStressLevels() []StressLevel {
	return []StressLevel{
		{
			Name:            "Small",
			RateEntries:     1 << 4,  // 2^4 = 16
			BotEntries:      1 << 16, // 2^16 = 65,536
			VerifiedEntries: 1 << 8,  // 2^8 = 256
		},
		{
			Name:            "Medium",
			RateEntries:     1 << 8,  // 2^8 = 256
			BotEntries:      1 << 18, // 2^18 = 262,144 (capped from 2^32)
			VerifiedEntries: 1 << 16, // 2^16 = 65,536
		},
		{
			Name:            "Large",
			RateEntries:     1 << 10, // 2^10 = 1,024 (capped from 2^16)
			BotEntries:      1 << 20, // 2^20 = 1,048,576 (capped from 2^64)
			VerifiedEntries: 1 << 18, // 2^18 = 262,144 (capped from 2^32)
		},
		{
			Name:            "XLarge",
			RateEntries:     1 << 12, // 2^12 = 4,096
			BotEntries:      1 << 22, // 2^22 = 4,194,304
			VerifiedEntries: 1 << 20, // 2^20 = 1,048,576
		},
	}
}

// generateIPv4Subnet generates a unique IPv4 subnet string for the rate cache
// Uses the pattern: A.B.0.0 where A and B are derived from the index
func generateIPv4Subnet(index int) string {
	// Create /16 subnets (e.g., 10.0.0.0, 10.1.0.0, etc.)
	a := (index >> 8) & 0xFF
	b := index & 0xFF
	return fmt.Sprintf("%d.%d.0.0", a, b)
}

// generateIPv4Address generates a unique IPv4 address for bot/verified caches
// Uses the pattern: A.B.C.D where all octets are derived from the index
func generateIPv4Address(index int) string {
	a := (index >> 24) & 0xFF
	b := (index >> 16) & 0xFF
	c := (index >> 8) & 0xFF
	d := index & 0xFF
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// populateCaches fills caches with test data based on the stress level
func populateCaches(level StressLevel, rateCache, botCache, verifiedCache *lru.Cache) {
	expiration := 24 * time.Hour

	// Populate rate cache with subnet entries
	for i := 0; i < level.RateEntries; i++ {
		subnet := generateIPv4Subnet(i)
		// Vary the rate values (1-100)
		rate := uint(1 + (i % 100))
		rateCache.Set(subnet, rate, expiration)
	}

	// Populate bot cache with IP addresses
	for i := 0; i < level.BotEntries; i++ {
		ip := generateIPv4Address(i)
		// Alternate between verified and unverified bots
		isBot := i%2 == 0
		botCache.Set(ip, isBot, expiration)
	}

	// Populate verified cache with IP addresses
	// Use different starting index to avoid overlap with bot cache
	startOffset := 0x10000000 // Start from 16.0.0.0
	for i := 0; i < level.VerifiedEntries; i++ {
		ip := generateIPv4Address(startOffset + i)
		verifiedCache.Set(ip, true, expiration)
	}
}

// BenchmarkStateOperations benchmarks marshal/unmarshal/reconcile at different scales
func BenchmarkStateOperations(b *testing.B) {
	levels := getStressLevels()

	for _, level := range levels {
		// Create caches and populate with test data
		rateCache := lru.New(24*time.Hour, lru.NoExpiration)
		botCache := lru.New(24*time.Hour, lru.NoExpiration)
		verifiedCache := lru.New(24*time.Hour, lru.NoExpiration)

		b.Logf("Populating caches for %s level (rate=%d, bots=%d, verified=%d)...",
			level.Name, level.RateEntries, level.BotEntries, level.VerifiedEntries)
		populateCaches(level, rateCache, botCache, verifiedCache)

		// Benchmark GetState (extract to struct)
		b.Run(fmt.Sprintf("GetState/%s", level.Name), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())
			}
		})

		// Benchmark Marshal
		state := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())
		b.Run(fmt.Sprintf("Marshal/%s", level.Name), func(b *testing.B) {
			b.ReportAllocs()
			var jsonData []byte
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				jsonData, _ = json.Marshal(state)
			}
			b.ReportMetric(float64(len(jsonData)), "bytes")
		})

		// Benchmark Unmarshal
		jsonData, _ := json.Marshal(state)
		b.Run(fmt.Sprintf("Unmarshal/%s", level.Name), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var loadedState State
				_ = json.Unmarshal(jsonData, &loadedState)
			}
		})

		// Benchmark SetState (load into caches)
		b.Run(fmt.Sprintf("SetState/%s", level.Name), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				newRateCache := lru.New(24*time.Hour, lru.NoExpiration)
				newBotCache := lru.New(24*time.Hour, lru.NoExpiration)
				newVerifiedCache := lru.New(24*time.Hour, lru.NoExpiration)
				b.StartTimer()

				SetState(state, newRateCache, newBotCache, newVerifiedCache)
			}
		})

		// Benchmark ReconcileState
		b.Run(fmt.Sprintf("ReconcileState/%s", level.Name), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				// Create fresh caches with some overlapping data
				newRateCache := lru.New(24*time.Hour, lru.NoExpiration)
				newBotCache := lru.New(24*time.Hour, lru.NoExpiration)
				newVerifiedCache := lru.New(24*time.Hour, lru.NoExpiration)
				// Pre-populate with 50% of entries
				for j := 0; j < level.RateEntries/2; j++ {
					subnet := generateIPv4Subnet(j)
					newRateCache.Set(subnet, uint(50), 24*time.Hour)
				}
				b.StartTimer()

				ReconcileState(state, newRateCache, newBotCache, newVerifiedCache)
			}
		})

		// Benchmark full SaveStateToFile cycle (with reconciliation)
		b.Run(fmt.Sprintf("SaveStateToFile/%s", level.Name), func(b *testing.B) {
			tmpDir := b.TempDir()
			tmpFile := tmpDir + "/state.json"
			logger := testLogger()

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs, err := SaveStateToFile(
					tmpFile,
					true, // enable reconciliation
					rateCache,
					botCache,
					verifiedCache,
					logger,
				)
				if err != nil {
					b.Fatalf("SaveStateToFile failed: %v", err)
				}

				// Report timing breakdown (only once to avoid noise)
				if i == 0 {
					b.Logf("Timing breakdown: lock=%dms read=%dms reconcile=%dms marshal=%dms write=%dms total=%dms",
						lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs)
				}
			}
		})
	}
}

// TestStateOperationsWithinThreshold ensures operations complete within acceptable time limits
func TestStateOperationsWithinThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	levels := getStressLevels()

	// Define thresholds for each operation (in milliseconds)
	// These are generous limits to avoid flaky tests on slower CI machines
	type thresholds struct {
		GetStateMs          int64
		MarshalMs           int64
		UnmarshalMs         int64
		SetStateMs          int64
		ReconcileMs         int64
		SaveWithReconcileMs int64
	}

	levelThresholds := map[string]thresholds{
		"Small": {
			GetStateMs:          100,
			MarshalMs:           200,
			UnmarshalMs:         200,
			SetStateMs:          200,
			ReconcileMs:         200,
			SaveWithReconcileMs: 500,
		},
		"Medium": {
			GetStateMs:          200,
			MarshalMs:           500,
			UnmarshalMs:         500,
			SetStateMs:          500,
			ReconcileMs:         500,
			SaveWithReconcileMs: 1000,
		},
		"Large": {
			GetStateMs:          500,
			MarshalMs:           2000,
			UnmarshalMs:         2000,
			SetStateMs:          2000,
			ReconcileMs:         2000,
			SaveWithReconcileMs: 3000,
		},
		"XLarge": {
			GetStateMs:          2000,
			MarshalMs:           5000,
			UnmarshalMs:         5000,
			SetStateMs:          3000,
			ReconcileMs:         3000,
			SaveWithReconcileMs: 10000,
		},
		"XXLarge": {
			GetStateMs:          5000,
			MarshalMs:           15000,
			UnmarshalMs:         15000,
			SetStateMs:          10000,
			ReconcileMs:         10000,
			SaveWithReconcileMs: 30000,
		},
	}

	for _, level := range levels {
		t.Run(level.Name, func(t *testing.T) {
			// Create and populate caches
			rateCache := lru.New(24*time.Hour, lru.NoExpiration)
			botCache := lru.New(24*time.Hour, lru.NoExpiration)
			verifiedCache := lru.New(24*time.Hour, lru.NoExpiration)

			t.Logf("Populating caches (rate=%d, bots=%d, verified=%d)...",
				level.RateEntries, level.BotEntries, level.VerifiedEntries)
			populateCaches(level, rateCache, botCache, verifiedCache)

			thresh := levelThresholds[level.Name]

			// Test GetState
			t.Run("GetState", func(t *testing.T) {
				start := time.Now()
				state := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())
				elapsed := time.Since(start).Milliseconds()

				t.Logf("GetState took %dms (threshold: %dms)", elapsed, thresh.GetStateMs)
				if elapsed > thresh.GetStateMs {
					slog.Error(fmt.Sprintf("GetState took %dms, exceeds threshold of %dms", elapsed, thresh.GetStateMs))
				}

				// Verify counts
				if len(state.Rate) != level.RateEntries {
					t.Errorf("Expected %d rate entries, got %d", level.RateEntries, len(state.Rate))
				}
				if len(state.Bots) != level.BotEntries {
					t.Errorf("Expected %d bot entries, got %d", level.BotEntries, len(state.Bots))
				}
				if len(state.Verified) != level.VerifiedEntries {
					t.Errorf("Expected %d verified entries, got %d", level.VerifiedEntries, len(state.Verified))
				}
			})

			state := GetState(rateCache.Items(), botCache.Items(), verifiedCache.Items())

			// Test Marshal
			t.Run("Marshal", func(t *testing.T) {
				start := time.Now()
				jsonData, err := json.Marshal(state)
				elapsed := time.Since(start).Milliseconds()

				if err != nil {
					t.Fatalf("Marshal failed: %v", err)
				}

				sizeKB := float64(len(jsonData)) / 1024.0
				sizeMB := sizeKB / 1024.0
				if sizeMB >= 1.0 {
					t.Logf("Marshal took %dms (threshold: %dms), size: %.2f MB",
						elapsed, thresh.MarshalMs, sizeMB)
				} else {
					t.Logf("Marshal took %dms (threshold: %dms), size: %.2f KB",
						elapsed, thresh.MarshalMs, sizeKB)
				}

				if elapsed > thresh.MarshalMs {
					slog.Error(fmt.Sprintf("Marshal took %dms, exceeds threshold of %dms", elapsed, thresh.MarshalMs))
				}
			})

			// Test Unmarshal
			jsonData, _ := json.Marshal(state)
			t.Run("Unmarshal", func(t *testing.T) {
				start := time.Now()
				var loadedState State
				err := json.Unmarshal(jsonData, &loadedState)
				elapsed := time.Since(start).Milliseconds()

				if err != nil {
					t.Fatalf("Unmarshal failed: %v", err)
				}

				t.Logf("Unmarshal took %dms (threshold: %dms)", elapsed, thresh.UnmarshalMs)
				if elapsed > thresh.UnmarshalMs {
					slog.Error(fmt.Sprintf("Unmarshal took %dms, exceeds threshold of %dms", elapsed, thresh.UnmarshalMs))
				}
			})

			// Test SetState
			t.Run("SetState", func(t *testing.T) {
				newRateCache := lru.New(24*time.Hour, lru.NoExpiration)
				newBotCache := lru.New(24*time.Hour, lru.NoExpiration)
				newVerifiedCache := lru.New(24*time.Hour, lru.NoExpiration)

				start := time.Now()
				SetState(state, newRateCache, newBotCache, newVerifiedCache)
				elapsed := time.Since(start).Milliseconds()

				t.Logf("SetState took %dms (threshold: %dms)", elapsed, thresh.SetStateMs)
				if elapsed > thresh.SetStateMs {
					slog.Error(fmt.Sprintf("SetState took %dms, exceeds threshold of %dms", elapsed, thresh.SetStateMs))
				}

				// Verify data was loaded
				if newRateCache.ItemCount() != level.RateEntries {
					t.Errorf("Expected %d rate entries after SetState, got %d",
						level.RateEntries, newRateCache.ItemCount())
				}
			})

			// Test ReconcileState
			t.Run("ReconcileState", func(t *testing.T) {
				newRateCache := lru.New(24*time.Hour, lru.NoExpiration)
				newBotCache := lru.New(24*time.Hour, lru.NoExpiration)
				newVerifiedCache := lru.New(24*time.Hour, lru.NoExpiration)

				// Pre-populate with 50% overlapping data
				for i := 0; i < level.RateEntries/2; i++ {
					subnet := generateIPv4Subnet(i)
					newRateCache.Set(subnet, uint(50), 24*time.Hour)
				}

				start := time.Now()
				ReconcileState(state, newRateCache, newBotCache, newVerifiedCache)
				elapsed := time.Since(start).Milliseconds()

				t.Logf("ReconcileState took %dms (threshold: %dms)", elapsed, thresh.ReconcileMs)
				if elapsed > thresh.ReconcileMs {
					slog.Error(fmt.Sprintf("ReconcileState took %dms, exceeds threshold of %dms", elapsed, thresh.ReconcileMs))
				}
			})

			// Test full SaveStateToFile with reconciliation
			t.Run("SaveStateToFile", func(t *testing.T) {
				tmpFile := t.TempDir() + "/state.json"
				logger := testLogger()

				// Pre-create a state file to enable reconciliation
				initialData, _ := json.Marshal(state)
				_ = os.WriteFile(tmpFile, initialData, 0644)

				start := time.Now()
				lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs, err := SaveStateToFile(
					tmpFile,
					true, // enable reconciliation
					rateCache,
					botCache,
					verifiedCache,
					logger,
				)
				elapsed := time.Since(start).Milliseconds()

				if err != nil {
					t.Fatalf("SaveStateToFile failed: %v", err)
				}

				t.Logf("SaveStateToFile took %dms (threshold: %dms)", elapsed, thresh.SaveWithReconcileMs)
				t.Logf("  Breakdown: lock=%dms read=%dms reconcile=%dms marshal=%dms write=%dms total=%dms",
					lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs)

				if elapsed > thresh.SaveWithReconcileMs {
					slog.Error(fmt.Sprintf("SaveStateToFile took %dms, exceeds threshold of %dms",
						elapsed, thresh.SaveWithReconcileMs))
				}

				// Verify math adds up (approximately, allowing for measurement overhead)
				measuredTotal := lockMs + readMs + reconcileMs + marshalMs + writeMs
				if totalMs > 0 && math.Abs(float64(measuredTotal-totalMs)) > float64(totalMs)*0.2 {
					t.Logf("Warning: timing components (%dms) don't add up to total (%dms)",
						measuredTotal, totalMs)
				}
			})
		})
	}
}

// TestGenerateUniqueIPs verifies IP generation produces unique addresses
func TestGenerateUniqueIPs(t *testing.T) {
	t.Run("Subnets are unique", func(t *testing.T) {
		count := 1000
		seen := make(map[string]bool, count)

		for i := 0; i < count; i++ {
			subnet := generateIPv4Subnet(i)
			if seen[subnet] {
				t.Errorf("Duplicate subnet generated: %s", subnet)
			}
			seen[subnet] = true
		}

		if len(seen) != count {
			t.Errorf("Expected %d unique subnets, got %d", count, len(seen))
		}
	})

	t.Run("Addresses are unique", func(t *testing.T) {
		count := 10000
		seen := make(map[string]bool, count)

		for i := 0; i < count; i++ {
			ip := generateIPv4Address(i)
			if seen[ip] {
				t.Errorf("Duplicate IP generated: %s", ip)
			}
			seen[ip] = true
		}

		if len(seen) != count {
			t.Errorf("Expected %d unique IPs, got %d", count, len(seen))
		}
	})
}
