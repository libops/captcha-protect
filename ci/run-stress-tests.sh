#!/usr/bin/env bash

set -eou pipefail

# Determine correct path to internal/state (works from root or ci/ directory)
if [ -d "./internal/state" ]; then
    STATE_PATH="./internal/state"
elif [ -d "../internal/state" ]; then
    STATE_PATH="../internal/state"
else
    echo "Error: Cannot find internal/state directory"
    exit 1
fi

# Determine correct path to parser (works from root or ci/ directory)
if [ -d "./ci/parse-stress-results" ]; then
    PARSER_PATH="./ci/parse-stress-results"
elif [ -d "./parse-stress-results" ]; then
    PARSER_PATH="./parse-stress-results"
else
    echo "Error: Cannot find parse-stress-results directory"
    exit 1
fi

echo "Running State Persistence Stress Tests"
echo "========================================"
echo ""
echo "Testing Small, Medium, Large, and XLarge scales..."
echo ""

# Run tests with JSON output and parse with Go program
go test -json -timeout 5m -run 'TestStateOperationsWithinThreshold' "$STATE_PATH" | \
    go run "$PARSER_PATH/main.go"
