package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type TestEvent struct {
	Time    string  `json:"Time"`
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

type TestResult struct {
	Name      string
	Entries   string
	Size      string
	Time      int64 // milliseconds
	Threshold int64 // milliseconds
	Passed    bool
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	// Patterns to extract data
	sizePattern := regexp.MustCompile(`size: ([\d.]+) MB`)
	timePattern := regexp.MustCompile(`took (\d+)ms`)

	results := make(map[string]*TestResult)
	currentTest := ""

	// Initialize known tests
	results["Small"] = &TestResult{Name: "Small", Entries: "16 rate / 65K bots / 256 verified", Threshold: 500}
	results["Medium"] = &TestResult{Name: "Medium", Entries: "256 rate / 262K bots / 65K verified", Threshold: 1000}
	results["Large"] = &TestResult{Name: "Large", Entries: "1K rate / 1M bots / 262K verified", Threshold: 3000}
	results["XLarge"] = &TestResult{Name: "XLarge", Entries: "4K rate / 4.2M bots / 1M verified", Threshold: 10000}

	for scanner.Scan() {
		line := scanner.Text()

		var event TestEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}

		// Track which test we're in
		if event.Action == "run" && strings.Contains(event.Test, "TestStateOperationsWithinThreshold/") {
			parts := strings.Split(event.Test, "/")
			if len(parts) >= 2 {
				testLevel := parts[1]
				if _, ok := results[testLevel]; ok {
					currentTest = testLevel
				}
			}
		}

		// Extract size from Marshal test
		if event.Output != "" && strings.Contains(event.Output, "Marshal took") && strings.Contains(event.Output, "size:") {
			if matches := sizePattern.FindStringSubmatch(event.Output); len(matches) > 1 {
				if currentTest != "" && results[currentTest] != nil {
					results[currentTest].Size = matches[1] + " MB"
				}
			}
		}

		// Extract time from SaveStateToFile test
		if event.Output != "" && strings.Contains(event.Output, "SaveStateToFile took") {
			if matches := timePattern.FindStringSubmatch(event.Output); len(matches) > 1 {
				if timeMs, err := strconv.ParseInt(matches[1], 10, 64); err == nil {
					if currentTest != "" && results[currentTest] != nil {
						results[currentTest].Time = timeMs
						results[currentTest].Passed = timeMs <= results[currentTest].Threshold
					}
				}
			}
		}
	}

	// Check if we should output Markdown (for CI) or plain text (for local)
	inCI := os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != ""

	allPassed := true
	order := []string{"Small", "Medium", "Large", "XLarge"}

	if inCI {
		// Markdown table for GitHub PR comments
		fmt.Println("\n### Stress Test Summary")
		fmt.Println("| Scale | Entries | JSON Size | Time | Threshold | Status |")
		fmt.Println("|-------|---------|-----------|------|-----------|--------|")

		for _, name := range order {
			result := results[name]
			if result.Time == 0 {
				continue // Skip if no data
			}

			size := result.Size
			if size == "" {
				size = "N/A"
			}

			status := "✅"
			if !result.Passed {
				status = "❌"
				allPassed = false
			}

			thresholdStr := formatThreshold(result.Threshold)

			fmt.Printf("| %s | %s | %s | %dms | %s | %s |\n",
				result.Name,
				result.Entries,
				size,
				result.Time,
				thresholdStr,
				status)
		}
		fmt.Println()

		// In CI, just report metrics without failing
		fmt.Println("ℹ️ Performance metrics reported (thresholds informational only in CI)")
		if !allPassed {
			fmt.Println("   Note: Some tests exceeded local development thresholds, but this is expected on CI runners")
		}

	} else {
		// ASCII table for local terminal
		fmt.Println("\nStress Test Summary:")
		fmt.Println("============================================================================================================")
		fmt.Printf("%-8s | %-35s | %-10s | %-15s | %-10s | %-6s\n", "Scale", "Entries", "JSON Size", "Time", "Threshold", "Status")
		fmt.Println("------------------------------------------------------------------------------------------------------------")

		for _, name := range order {
			result := results[name]
			if result.Time == 0 {
				continue // Skip if no data
			}

			size := result.Size
			if size == "" {
				size = "N/A"
			}

			status := "✅"
			if !result.Passed {
				status = "❌"
				allPassed = false
			}

			thresholdStr := formatThreshold(result.Threshold)

			fmt.Printf("%-8s | %-35s | %-10s | %-15s | %-10s | %s\n",
				result.Name,
				result.Entries,
				size,
				fmt.Sprintf("%dms", result.Time),
				thresholdStr,
				status)
		}
		fmt.Println()
		// Local development: enforce thresholds
		if allPassed {
			fmt.Println("✅ All stress tests passed within thresholds")
		} else {
			fmt.Println("❌ Some stress tests exceeded thresholds")
			os.Exit(1)
		}
	}
}

func formatThreshold(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("<%dms", ms)
	}
	return fmt.Sprintf("<%ds", ms/1000)
}
