# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Traefik middleware plugin that protects websites from bot traffic by challenging individual IPs with CAPTCHAs when traffic spikes are detected from their subnet. The plugin supports Cloudflare Turnstile, Google reCAPTCHA, and hCaptcha.

**Key concept**: Instead of rate limiting individual IPs, this plugin monitors traffic at the subnet level (e.g., /16 for IPv4, /64 for IPv6) and only challenges specific IPs when their entire subnet exceeds a configured rate limit.

## Architecture

### Core Components

- **main.go** (`main.go:1-761`): Contains the entire middleware implementation in a single file
  - `CaptchaProtect` struct: Main middleware handler with rate limiting, bot detection, and challenge serving
  - `Config` struct: Configuration from Traefik labels
  - Three in-memory caches (using `github.com/patrickmn/go-cache`):
    - `rateCache`: Tracks request counts per subnet (TTL = `window` config value)
    - `verifiedCache`: Stores IPs that have passed challenges (24h default TTL)
    - `botCache`: Caches reverse DNS lookups for bot verification (1h TTL)
  - **Why go-cache instead of sync.Map?** The plugin requires automatic TTL-based expiration for all caches. `sync.Map` has no built-in expiration mechanism, requiring manual cleanup goroutines. `go-cache` provides thread-safe maps with automatic expiration and cleanup.

### Request Flow Decision Tree

The middleware follows this decision order (see `shouldApply()` at `main.go:422-453`):

1. Check if HTTP method is protected (default: GET, HEAD)
2. Check if IP already verified (passed challenge recently)
3. Check if IP is in exemptIps (private ranges + configured exemptions)
4. Check if IP is a good bot (reverse DNS matches goodBots list)
5. Check if user agent is exempt
6. Check if route matches protection rules (prefix/suffix/regex matching)
7. If protected, increment subnet counter and check rate limit
8. If rate limit exceeded, serve challenge or redirect to challenge page

### Internal Packages

- **internal/helper/**: Utility functions
  - `ip.go`: IP parsing, CIDR matching, reverse DNS lookups for bot verification
  - `tmpl.go`: Default challenge template (embedded fallback)
- **internal/log/**: Structured logging with slog
- **internal/state/**: State serialization for persistent storage across restarts

### Challenge Modes

Two modes for serving challenges:

1. **Redirect mode** (default): `challengeURL: "/challenge"` - Redirects to dedicated challenge page
2. **Inline mode**: `challengeURL: ""` - Serves challenge on the same page that triggered rate limit

## Development Commands

### Running Tests

```bash
# Run unit tests
go test -v -race ./...

# Run single test
go test -v -race -run TestParseIp

# Run integration tests (requires Docker)
cd ci && go run test.go
```

### Linting and Formatting

```bash
# Run golangci-lint locally
golangci-lint run

# Format code
gofmt -w .

# Check if go.mod is tidy
go mod tidy && git diff --exit-code go.mod go.sum

# Update vendored dependencies
go mod vendor
```

### CI/CD

The GitHub Actions workflow (`.github/workflows/lint-test.yml`) runs on every push:
1. golangci-lint
2. Validates `.traefik.yml` with yq
3. Checks `go mod tidy` and `go mod vendor` are up-to-date
4. Runs unit tests with race detector
5. Runs integration tests against Traefik v2.11, v3.0, v3.1, v3.2, v3.3, v3.4

### Integration Testing

The `ci/` directory contains a full integration test:
- Spins up Traefik + nginx with docker-compose
- Generates 100 unique public IPs from different subnets
- Makes parallel requests to verify rate limiting behavior
- Tests state persistence across container restarts
- Validates stats endpoint JSON

To run: `cd ci && go run test.go`

## Key Implementation Details

### Route Matching Modes

Three modes configured via `mode` parameter (defaults to "prefix"):

1. **prefix**: Fast string prefix matching (`strings.HasPrefix`)
2. **suffix**: Matches route suffixes (useful for specific endpoints)
3. **regex**: Full regex support (13x slower than prefix, use only when needed)

Regex is significantly slower (~41ns vs ~3.4ns per operation) - see README benchmark section.

### IP Subnet Calculation

- IPv4: Masks IPs to configured subnet (default /16 means `192.168.x.x` → `192.168.0.0`)
- IPv6: Default /64 subnet mask
- Implementation at `main.go:621-642`

### State Persistence

When `persistentStateFile` is configured:
- State saves every 10 seconds (with 0-2s random jitter) to JSON file (`saveState()` at `main.go:716-746`)
- Uses file locking (`.lock` files) to prevent concurrent writes (`internal/state/state.go:61-129`)
- On startup, loads previous state from file (`loadState()` at `main.go:729-761`)
- Contains: rate limits per subnet, bot verification cache, verified IPs
- **Important**: Each middleware instance runs its own save goroutine. If multiple instances share the same `persistentStateFile`, they will write more frequently (e.g., 2 instances = writes every ~5 seconds)
- **State Reconciliation**: When `enableStateReconciliation: "true"`, each save performs a read-modify-write cycle to merge state from other instances. This adds I/O overhead but prevents data loss in multi-instance deployments (see `internal/state/state.go:86-100`)
- **Performance Characteristics** (based on stress tests in `internal/state/state_stress_test.go`):
  - **Small scale** (<100K IPs): Reconciliation adds <50ms overhead per cycle
  - **Medium scale** (250K IPs): Reconciliation adds ~240ms overhead per cycle
  - **Large scale** (1M IPs): Reconciliation adds ~1s overhead per cycle
  - **XLarge scale** (5M IPs): Reconciliation adds ~5s overhead per cycle (approaching 10s save window limit)
  - **Recommendation**: Do not enable `enableStateReconciliation` for sites with >1M unique visitors

**Why not Redis?** Traefik plugins are loaded via Yaegi (a Go interpreter), which has significant limitations:
- Yaegi cannot interpret Go packages that use `unsafe`, cgo, or complex reflection patterns
- Popular Redis clients like `go-redis/redis` are incompatible with Yaegi

**Current solution**: File-based persistence with reconciliation avoids these issues. Local caches remain fast (no network overhead), state saves are batched (every 10s), and reconciliation handles conflicts without complex coordination. The tradeoff is accepting slightly stale data across instances (max 10s delay) rather than the complexity and performance cost of real-time Redis synchronization.

### Good Bot Detection

To avoid SEO impact, the plugin allows "good bots" to bypass rate limits:
- Performs reverse DNS lookup on IP (`internal/helper/ip.go`)
- Checks if hostname ends with configured second-level domain (e.g., "googlebot.com")
- Results cached in `botCache` to avoid repeated DNS lookups
- Optional `protectParameters: "true"` forces rate limiting even for good bots if URL contains query parameters

### File Extension Filtering

By default, only HTML files are rate-limited (to prevent CSS/JS/images from consuming rate limit quota). Configure `protectFileExtensions` to add more file types.

## Configuration

Configuration comes from Traefik labels. See `.traefik.yml` for the plugin manifest.

Key defaults:
- `rateLimit: 20` requests per subnet
- `window: 86400` seconds (24 hours)
- `ipv4subnetMask: 16` (/16 = 65,536 IPs)
- `ipv6subnetMask: 64`
- `challengeStatusCode: 200` (or 429 for inline challenges)

## Testing Strategy

Unit tests (`main_test.go`) cover:
- IP parsing and subnet masking
- Route protection logic (prefix/suffix/regex)
- Client IP extraction from forwarded headers with depth traversal
- User agent exemption matching
- Challenge page serving with different status codes

Integration tests (`ci/test.go`) verify:
- Full request lifecycle with real Traefik/nginx
- Rate limiting behavior across multiple subnets
- State persistence across container restarts
- Stats endpoint functionality

## Traefik Plugin Constraints

- Must implement `http.Handler` interface
- Entry point: `New(ctx context.Context, next http.Handler, config *Config, name string)`
- Plugin loaded via Traefik's `--experimental.plugins` flag
- No external state allowed (must use in-memory caches or file persistence)
- Must be compatible with Traefik v2.11.1+
