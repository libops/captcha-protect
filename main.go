package captcha_protect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/libops/captcha-protect/internal/helper"
	plog "github.com/libops/captcha-protect/internal/log"
	"github.com/libops/captcha-protect/internal/state"

	lru "github.com/patrickmn/go-cache"
)

const (
	// StateSaveInterval is how often the persistent state file is written to disk
	StateSaveInterval = 10 * time.Second
	// StateSaveJitter is the maximum random jitter added to save interval to prevent thundering herd
	StateSaveJitter = 2 * time.Second

	// Default health check settings (disabled by default)
	DefaultHealthCheckPeriodSeconds    = 0 // How often to check captcha provider health
	DefaultHealthCheckFailureThreshold = 0 // Number of consecutive health check failures before opening circuit
)

type circuitState int

const (
	circuitClosed circuitState = iota // Normal operation, using primary provider
	circuitOpen                       // Circuit tripped, using fallback provider
)

type Config struct {
	RateLimit         uint   `json:"rateLimit"`
	Window            int64  `json:"window"`
	IPv4SubnetMask    int    `json:"ipv4subnetMask"`
	IPv6SubnetMask    int    `json:"ipv6subnetMask"`
	IPForwardedHeader string `json:"ipForwardedHeader"`
	IPDepth           int    `json:"ipDepth"`
	// ProtectParameters is a string instead of bool due to Traefik's label parsing limitations
	ProtectParameters     string   `json:"protectParameters"`
	ProtectRoutes         []string `json:"protectRoutes"`
	ExcludeRoutes         []string `json:"excludeRoutes"`
	ProtectFileExtensions []string `json:"protectFileExtensions"`
	ProtectHttpMethods    []string `json:"protectHttpMethods"`
	GoodBots              []string `json:"goodBots"`
	ExemptIPs             []string `json:"exemptIps"`
	ExemptUserAgents      []string `json:"exemptUserAgents"`
	ChallengeURL          string   `json:"challengeURL"`
	ChallengeTmpl         string   `json:"challengeTmpl"`
	ChallengeStatusCode   int      `json:"challengeStatusCode"`
	CaptchaProvider       string   `json:"captchaProvider"`
	SiteKey               string   `json:"siteKey"`
	SecretKey             string   `json:"secretKey"`
	// EnableStatsPage is a string instead of bool due to Traefik's label parsing limitations
	EnableStatsPage     string `json:"enableStatsPage"`
	LogLevel            string `json:"loglevel,omitempty"`
	PersistentStateFile string `json:"persistentStateFile"`
	// EnableStateReconciliation is a string instead of bool due to Traefik's label parsing limitations
	// When enabled, the plugin will read and merge state from disk before each save to prevent
	// multiple instances from overwriting each other's data. This adds extra I/O overhead.
	// Only enable this if running multiple plugin instances sharing the same state file.
	// Performance warning: Not recommended for sites with >1M unique visitors (see internal/state/state_stress_test.go).
	EnableStateReconciliation string `json:"enableStateReconciliation"`
	EnableGooglebotIPCheck    string `json:"enableGooglebotIPCheck"`
	Mode                      string `json:"mode"`
	PeriodSeconds             int    `json:"periodSeconds"`
	FailureThreshold          int    `json:"failureThreshold"`
}

type CaptchaProtect struct {
	next               http.Handler
	name               string
	config             *Config
	log                *slog.Logger
	httpClient         *http.Client
	rateCache          *lru.Cache
	verifiedCache      *lru.Cache
	botCache           *lru.Cache
	googlebotIPs       *helper.GooglebotIPs
	captchaConfig      CaptchaConfig
	exemptIps          []*net.IPNet
	tmpl               *template.Template
	ipv4Mask           net.IPMask
	ipv6Mask           net.IPMask
	protectRoutesRegex []*regexp.Regexp
	excludeRoutesRegex []*regexp.Regexp

	// Circuit breaker fields
	mu                      sync.RWMutex
	circuitState            circuitState
	healthCheckFailureCount int
	hasFallbackProvider     bool
}

type CaptchaConfig struct {
	js       string
	key      string
	validate string
}

type captchaResponse struct {
	Success bool `json:"success"`
}

func CreateConfig() *Config {
	return &Config{
		RateLimit:                 20,
		Window:                    86400,
		IPv4SubnetMask:            16,
		IPv6SubnetMask:            64,
		IPForwardedHeader:         "",
		ProtectParameters:         "false",
		ProtectRoutes:             []string{},
		ExcludeRoutes:             []string{},
		ProtectHttpMethods:        []string{},
		ProtectFileExtensions:     []string{},
		GoodBots:                  []string{},
		ExemptIPs:                 []string{},
		ExemptUserAgents:          []string{},
		ChallengeURL:              "/challenge",
		ChallengeTmpl:             "challenge.tmpl.html",
		ChallengeStatusCode:       0,
		EnableStatsPage:           "false",
		LogLevel:                  "INFO",
		IPDepth:                   0,
		CaptchaProvider:           "turnstile",
		Mode:                      "prefix",
		EnableStateReconciliation: "false",
		EnableGooglebotIPCheck:    "false",
		PeriodSeconds:             DefaultHealthCheckPeriodSeconds,
		FailureThreshold:          DefaultHealthCheckFailureThreshold,
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return NewCaptchaProtect(ctx, next, config, name)
}

func NewCaptchaProtect(ctx context.Context, next http.Handler, config *Config, name string) (*CaptchaProtect, error) {
	log := plog.New(config.LogLevel)

	// Validate required config
	if config.SiteKey == "" {
		return nil, fmt.Errorf("siteKey is required")
	}
	if config.SecretKey == "" {
		return nil, fmt.Errorf("secretKey is required")
	}
	if config.Window <= 0 {
		return nil, fmt.Errorf("window must be positive, got %d", config.Window)
	}

	expiration := time.Duration(config.Window) * time.Second
	log.Debug("Captcha config", "config", config)

	if len(config.ProtectRoutes) == 0 && config.Mode != "suffix" {
		return nil, fmt.Errorf("you must protect at least one route with the protectRoutes config value. / will cover your entire site")
	}

	protectRoutesRegex := []*regexp.Regexp{}
	excludeRoutesRegex := []*regexp.Regexp{}
	if config.Mode == "regex" {
		for _, r := range config.ProtectRoutes {
			cr, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in protectRoutes: %s", r)
			}
			protectRoutesRegex = append(protectRoutesRegex, cr)
		}
		for _, r := range config.ExcludeRoutes {
			cr, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in excludeRoutes: %s", r)
			}
			excludeRoutesRegex = append(excludeRoutesRegex, cr)
		}
	} else if config.Mode != "prefix" && config.Mode != "suffix" {
		return nil, fmt.Errorf("unknown mode: %s. Supported values are prefix, suffix, and regex", config.Mode)
	}

	// put exempt user agents in lowercase for quicker comparisons
	ua := []string{}
	for _, a := range config.ExemptUserAgents {
		ua = append(ua, strings.ToLower(a))
	}
	config.ExemptUserAgents = ua

	if config.ChallengeURL == "/" {
		return nil, fmt.Errorf("your challenge URL can not be the entire site. Default is `/challenge`. A blank value will have challenges presented on the visit that trips the rate limit")
	}

	// when challenging on the same page that tripped the rate limiter
	// add a url parameter to detect on
	if config.ChallengeURL == "" {
		config.ChallengeURL = "?challenge=true"
	}

	if len(config.ProtectHttpMethods) == 0 {
		config.ProtectHttpMethods = []string{
			"GET",
			"HEAD",
		}
	}
	config.ParseHttpMethods(log)

	var tmpl *template.Template
	if _, err := os.Stat(config.ChallengeTmpl); os.IsNotExist(err) {
		log.Warn("Unable to find template file. Using default template", "challengeTmpl", config.ChallengeTmpl)
		ts := helper.GetDefaultTmpl()
		tmpl, err = template.New("challenge").Parse(ts)
		if err != nil {
			return nil, fmt.Errorf("unable to parse challenge template: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error checking for template file %s: %v", config.ChallengeTmpl, err)
	} else {
		tmpl, err = template.ParseFiles(config.ChallengeTmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to parse challenge template file %s: %v", config.ChallengeTmpl, err)
		}
	}

	// Always protect HTML files by default to ensure the main content is rate-limited.
	// This prevents users from accidentally excluding HTML, which would break the protection.
	if !slices.Contains(config.ProtectFileExtensions, "html") {
		config.ProtectFileExtensions = append(config.ProtectFileExtensions, "html")
	}

	// transform exempt IP strings into what go can easily parse (net.IPNet)
	var ips []*net.IPNet
	exemptIps := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	exemptIps = append(exemptIps, config.ExemptIPs...)
	for _, ip := range exemptIps {
		parsedIp, err := helper.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", ip, err)
		}
		ips = append(ips, parsedIp)
	}

	bc := CaptchaProtect{
		next:   next,
		name:   name,
		config: config,
		log:    log,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		rateCache:          lru.New(expiration, 1*time.Minute),
		botCache:           lru.New(expiration, 1*time.Hour),
		verifiedCache:      lru.New(expiration, 1*time.Hour),
		exemptIps:          ips,
		tmpl:               tmpl,
		protectRoutesRegex: protectRoutesRegex,
		excludeRoutesRegex: excludeRoutesRegex,
	}

	// if a status code was not configured
	// retain the default set before this config option was added
	if config.ChallengeStatusCode == 0 {
		bc.config.ChallengeStatusCode = http.StatusOK
		if bc.ChallengeOnPage() {
			bc.config.ChallengeStatusCode = http.StatusTooManyRequests
		}
	}

	err := bc.SetIpv4Mask(config.IPv4SubnetMask)
	if err != nil {
		return nil, err
	}

	err = bc.SetIpv6Mask(config.IPv6SubnetMask)
	if err != nil {
		return nil, err
	}

	// set the captcha config based on the provider
	// thanks to https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/4708d76854c7ae95fa7313c46fbe21959be2fff1/pkg/captcha/captcha.go#L39-L55
	// for the struct/idea
	bc.captchaConfig = getCaptchaConfig(config.CaptchaProvider)
	if bc.captchaConfig.js == "" {
		return nil, fmt.Errorf("invalid captcha provider: %s", config.CaptchaProvider)
	}

	// Enable circuit breaker health checks if period/threshold are configured
	if config.CaptchaProvider != "poj" && config.PeriodSeconds > DefaultHealthCheckPeriodSeconds && config.FailureThreshold > DefaultHealthCheckFailureThreshold {
		bc.hasFallbackProvider = true
		bc.circuitState = circuitClosed
		log.Info("Circuit breaker enabled - will auto-pass when captcha provider is down",
			"provider", config.CaptchaProvider,
			"periodSeconds", config.PeriodSeconds,
			"failureThreshold", config.FailureThreshold)

		// Start health check goroutine
		childCtx, cancel := context.WithCancel(ctx)
		go bc.healthCheckLoop(childCtx)
		go func() {
			<-ctx.Done()
			log.Debug("Context canceled, stopping health check")
			cancel()
		}()
	}

	if config.PersistentStateFile != "" {
		bc.loadState()
		childCtx, cancel := context.WithCancel(ctx)
		go bc.saveState(childCtx)
		go func() {
			<-ctx.Done()
			bc.log.Debug("Context canceled, calling child cancel")
			cancel()
		}()
	}
	if config.EnableGooglebotIPCheck == "true" {
		log.Info("Googlebot IP check enabled")
		bc.googlebotIPs = helper.NewGooglebotIPs()
		childCtx, cancel := context.WithCancel(ctx)
		go bc.googlebotIPCheckLoop(childCtx)
		go func() {
			<-ctx.Done()
			log.Debug("Context canceled, stopping Googlebot IP check loop")
			cancel()
		}()
	}

	return &bc, nil
}

func (bc *CaptchaProtect) googlebotIPCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial fetch
	cidrs, err := helper.FetchGooglebotIPs(bc.log, bc.httpClient, "https://developers.google.com/static/search/apis/ipranges/googlebot.json")
	if err != nil {
		bc.log.Error("failed to fetch googlebot ips", "err", err)
	} else {
		bc.googlebotIPs.Update(cidrs, bc.log)
		bc.log.Info("Updated Googlebot IPs", "count", len(cidrs))
	}

	for {
		select {
		case <-ticker.C:
			cidrs, err := helper.FetchGooglebotIPs(bc.log, bc.httpClient, "https://developers.google.com/static/search/apis/ipranges/googlebot.json")
			if err != nil {
				bc.log.Error("failed to fetch googlebot ips", "err", err)
				continue
			}
			bc.googlebotIPs.Update(cidrs, bc.log)
			bc.log.Info("Updated Googlebot IPs", "count", len(cidrs))
		case <-ctx.Done():
			return
		}
	}
}

// getCaptchaConfig returns the captcha configuration for a given provider.
// Returns an empty CaptchaConfig if the provider is invalid.
func getCaptchaConfig(provider string) CaptchaConfig {
	switch provider {
	case "hcaptcha":
		return CaptchaConfig{
			js:       "https://hcaptcha.com/1/api.js",
			key:      "h-captcha",
			validate: "https://api.hcaptcha.com/siteverify",
		}
	case "recaptcha":
		return CaptchaConfig{
			js:       "https://www.google.com/recaptcha/api.js",
			key:      "g-recaptcha",
			validate: "https://www.google.com/recaptcha/api/siteverify",
		}
	case "turnstile":
		return CaptchaConfig{
			js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:      "cf-turnstile",
			validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		}
	case "poj":
		return CaptchaConfig{
			js:       "/captcha-protect-poj.js",
			key:      "poj-captcha",
			validate: "internal",
		}
	default:
		return CaptchaConfig{}
	}
}

// getActiveCaptchaConfig returns the currently active captcha config based on circuit breaker state.
// When circuit is open, returns the proof-of-javascript provider as a fallback.
func (bc *CaptchaProtect) getActiveCaptchaConfig() CaptchaConfig {
	if !bc.hasFallbackProvider {
		return bc.captchaConfig
	}

	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if bc.circuitState == circuitOpen {
		// Return proof-of-javascript provider as fallback
		return getCaptchaConfig("poj")
	}

	return bc.captchaConfig
}

// healthCheckLoop periodically checks the health of the primary captcha provider.
// If consecutive failures exceed the threshold, it opens the circuit to use the fallback provider.
func (bc *CaptchaProtect) healthCheckLoop(ctx context.Context) {
	period := time.Duration(bc.config.PeriodSeconds) * time.Second
	ticker := time.NewTicker(period)
	defer ticker.Stop()

	bc.log.Debug("Health check loop started", "period", period, "threshold", bc.config.FailureThreshold)

	for {
		select {
		case <-ticker.C:
			bc.performHealthCheck()
		case <-ctx.Done():
			bc.log.Debug("Health check loop stopped")
			return
		}
	}
}

// performHealthCheck executes a HEAD request to the primary captcha provider's JS file
// and updates the circuit breaker state based on the response.
func (bc *CaptchaProtect) performHealthCheck() {
	// Perform HEAD request to primary provider's JS URL
	req, err := http.NewRequest(http.MethodHead, bc.captchaConfig.js, nil)
	if err != nil {
		bc.log.Error("Failed to create health check request", "url", bc.captchaConfig.js, "err", err)
		bc.recordHealthCheckFailure()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := bc.httpClient.Do(req)
	if err != nil {
		bc.log.Warn("Health check failed for primary provider", "url", bc.captchaConfig.js, "err", err)
		bc.recordHealthCheckFailure()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound && resp.StatusCode >= 200 && resp.StatusCode < 500 {
		bc.recordHealthCheckSuccess()
		return
	}

	bc.log.Warn("Health check returned error status", "url", bc.captchaConfig.js, "statusCode", resp.StatusCode)
	bc.recordHealthCheckFailure()
}

// recordHealthCheckSuccess resets the failure count and closes the circuit if it was open.
func (bc *CaptchaProtect) recordHealthCheckSuccess() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	previousState := bc.circuitState
	previousFailureCount := bc.healthCheckFailureCount

	bc.healthCheckFailureCount = 0

	if bc.circuitState == circuitOpen {
		bc.circuitState = circuitClosed
		bc.log.Info("Circuit breaker closed, returning to primary captcha provider",
			"provider", bc.config.CaptchaProvider,
			"previousFailures", previousFailureCount)
	} else if previousFailureCount > 0 {
		bc.log.Debug("Health check success, failure count reset", "previousFailures", previousFailureCount)
	}

	if previousState == circuitOpen {
		bc.log.Debug("Circuit breaker state", "state", "closed", "failureCount", 0)
	}
}

// recordHealthCheckFailure increments the failure count and opens the circuit if threshold is reached.
func (bc *CaptchaProtect) recordHealthCheckFailure() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	bc.healthCheckFailureCount++

	bc.log.Debug("Health check failure recorded",
		"failureCount", bc.healthCheckFailureCount,
		"threshold", bc.config.FailureThreshold)

	if bc.healthCheckFailureCount >= bc.config.FailureThreshold && bc.circuitState == circuitClosed {
		bc.circuitState = circuitOpen
		bc.log.Error("Circuit breaker opened, auto-passing users through",
			"provider", bc.config.CaptchaProvider,
			"failureCount", bc.healthCheckFailureCount,
			"threshold", bc.config.FailureThreshold)
	}
}

func (bc *CaptchaProtect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP, ipRange := bc.getClientIP(req)

	// Serve proof-of-javascript JS
	if req.URL.Path == "/captcha-protect-poj.js" {
		bc.servePojJS(rw)
		return
	}

	challengeOnPage := bc.ChallengeOnPage()
	if challengeOnPage && req.Method == http.MethodPost {
		if req.URL.Query().Get("challenge") != "" {
			statusCode := bc.verifyChallengePage(rw, req, clientIP)
			bc.log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "status", statusCode, "useragent", req.UserAgent())
			return
		}
	} else if req.URL.Path == bc.config.ChallengeURL {
		switch req.Method {
		case http.MethodGet:
			destination := req.URL.Query().Get("destination")
			bc.log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "destination", destination, "useragent", req.UserAgent())
			bc.serveChallengePage(rw, destination)
		case http.MethodPost:
			statusCode := bc.verifyChallengePage(rw, req, clientIP)
			bc.log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "status", statusCode, "useragent", req.UserAgent())
		default:
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	} else if req.URL.Path == "/captcha-protect/stats" && bc.config.EnableStatsPage == "true" {
		bc.log.Info("Captcha stats", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
		bc.serveStatsPage(rw, clientIP)
		return
	}

	if !bc.shouldApply(req, clientIP) {
		bc.next.ServeHTTP(rw, req)
		return
	}
	bc.registerRequest(ipRange)

	if !bc.trippedRateLimit(ipRange) {
		bc.next.ServeHTTP(rw, req)
		return
	}

	encodedURI := url.QueryEscape(req.RequestURI)
	if bc.ChallengeOnPage() {
		bc.log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
		bc.serveChallengePage(rw, encodedURI)
		return
	}
	redirectURL := fmt.Sprintf("%s?destination=%s", bc.config.ChallengeURL, encodedURI)
	http.Redirect(rw, req, redirectURL, http.StatusFound)
}

// servePojJS serves the proof-of-javascript JavaScript implementation.
// This is used as a fallback captcha provider when external providers are unavailable.
func (bc *CaptchaProtect) servePojJS(rw http.ResponseWriter) {
	js := helper.GetPojJS()

	rw.Header().Set("Content-Type", "application/javascript")
	rw.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte(js))
}

func (bc *CaptchaProtect) serveChallengePage(rw http.ResponseWriter, destination string) {
	activeConfig := bc.getActiveCaptchaConfig()

	d := map[string]string{
		"SiteKey":      bc.config.SiteKey,
		"FrontendJS":   activeConfig.js,
		"FrontendKey":  activeConfig.key,
		"ChallengeURL": bc.config.ChallengeURL,
		"Destination":  destination,
	}

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")

	// have to write http status before executing the template
	// otherwise a 200 will get served by the template execution
	rw.WriteHeader(bc.config.ChallengeStatusCode)

	err := bc.tmpl.Execute(rw, d)
	if err != nil {
		bc.log.Error("unable to execute go template", "tmpl", bc.config.ChallengeTmpl, "err", err)
		// Can't change status code here, already written
		_, _ = rw.Write([]byte("\n<!-- Template execution failed -->"))
	}
}

func (bc *CaptchaProtect) verifyChallengePage(rw http.ResponseWriter, req *http.Request, ip string) int {
	activeConfig := bc.getActiveCaptchaConfig()

	response := req.FormValue(activeConfig.key + "-response")
	if response == "" {
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	var success bool
	exp := lru.DefaultExpiration

	// Handle proof-of-javascript verification
	if activeConfig.validate == "internal" {
		success = true
		// if the circuit is open, default to one hour TTL on verification
		if bc.circuitState == circuitOpen {
			exp = time.Hour * 1
		}
	} else {
		// Handle external captcha provider verification
		var body = url.Values{}
		body.Add("secret", bc.config.SecretKey)
		body.Add("response", response)
		resp, err := bc.httpClient.PostForm(activeConfig.validate, body)
		if err != nil {
			bc.log.Error("unable to validate captcha", "url", activeConfig.validate, "err", err)
			http.Error(rw, "Internal error", http.StatusInternalServerError)
			return http.StatusInternalServerError
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 500 {
			bc.recordHealthCheckFailure()
		}

		var captchaResponse captchaResponse
		err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
		if err != nil {
			bc.log.Error("unable to unmarshal captcha response", "url", activeConfig.validate, "err", err)
			http.Error(rw, "Internal error", http.StatusInternalServerError)
			return http.StatusInternalServerError
		}

		success = captchaResponse.Success
	}

	if success {
		bc.verifiedCache.Set(ip, true, exp)

		destination := req.FormValue("destination")
		if destination == "" {
			destination = "%2F"
		}
		u, err := url.QueryUnescape(destination)
		if err != nil {
			bc.log.Error("unable to unescape destination", "destination", destination, "err", err)
			u = "/"
		}
		http.Redirect(rw, req, u, http.StatusFound)
		return http.StatusFound
	}

	http.Error(rw, "Validation failed", http.StatusForbidden)

	return http.StatusForbidden
}

func (bc *CaptchaProtect) serveStatsPage(rw http.ResponseWriter, ip string) {
	// only allow excluded IPs from viewing
	if !helper.IsIpExcluded(ip, bc.exemptIps) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	state := state.GetState(bc.rateCache.Items(), bc.botCache.Items(), bc.verifiedCache.Items())
	jsonData, err := json.Marshal(state)
	if err != nil {
		bc.log.Error("failed to marshal JSON", "err", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_, err = rw.Write(jsonData)
	if err != nil {
		bc.log.Error("failed to write JSON on stats request", "err", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

}

func (bc *CaptchaProtect) shouldApply(req *http.Request, clientIP string) bool {
	if !slices.Contains(bc.config.ProtectHttpMethods, req.Method) {
		return false
	}

	_, verified := bc.verifiedCache.Get(clientIP)
	if verified {
		return false
	}

	if helper.IsIpExcluded(clientIP, bc.exemptIps) {
		return false
	}

	if bc.isGoodBot(req, clientIP) {
		return false
	}

	if bc.isGoodUserAgent(req.UserAgent()) {
		return false
	}

	if bc.config.Mode == "regex" {
		return bc.RouteIsProtectedRegex(req.URL.Path)
	}

	if bc.config.Mode == "suffix" {
		return bc.RouteIsProtectedSuffix(req.URL.Path)
	}

	return bc.RouteIsProtectedPrefix(req.URL.Path)
}

// isExtensionProtected checks if a file extension should be protected based on the configured list.
// Returns true if the path has no extension (likely HTML) or if the extension matches the protected list.
func (bc *CaptchaProtect) isExtensionProtected(path string) bool {
	ext := filepath.Ext(path)
	ext = strings.TrimPrefix(ext, ".")
	if ext == "" {
		return true
	}
	for _, protectedExt := range bc.config.ProtectFileExtensions {
		if strings.EqualFold(ext, protectedExt) {
			return true
		}
	}
	return false
}

func (bc *CaptchaProtect) RouteIsProtectedPrefix(path string) bool {
protected:
	for _, route := range bc.config.ProtectRoutes {
		if !strings.HasPrefix(path, route) {
			continue
		}

		// we're on a protected route - make sure this route doesn't have an exclusion
		for _, eRoute := range bc.config.ExcludeRoutes {
			if strings.HasPrefix(path, eRoute) {
				continue protected
			}
		}

		return bc.isExtensionProtected(path)
	}

	return false
}

func (bc *CaptchaProtect) RouteIsProtectedSuffix(path string) bool {
protected:
	for _, route := range bc.config.ProtectRoutes {
		cleanPath := path
		ext := filepath.Ext(path)
		if ext != "" {
			cleanPath = strings.TrimSuffix(path, ext)
		}
		if !strings.HasSuffix(cleanPath, route) {
			continue
		}

		// we're on a protected route - make sure this route doesn't have an exclusion
		for _, eRoute := range bc.config.ExcludeRoutes {
			if strings.HasPrefix(cleanPath, eRoute) {
				continue protected
			}
		}

		return bc.isExtensionProtected(path)
	}

	return false
}

func (bc *CaptchaProtect) isGoodUserAgent(ua string) bool {
	ua = strings.ToLower(ua)
	for _, agentPrefix := range bc.config.ExemptUserAgents {
		if strings.HasPrefix(ua, agentPrefix) {
			return true
		}
	}

	return false
}

func (bc *CaptchaProtect) RouteIsProtectedRegex(path string) bool {
protected:
	for _, routeRegex := range bc.protectRoutesRegex {
		matched := routeRegex.MatchString(path)
		if !matched {
			continue
		}

		for _, excludeRegex := range bc.excludeRoutesRegex {
			excluded := excludeRegex.MatchString(path)
			if excluded {
				continue protected
			}
		}

		return bc.isExtensionProtected(path)
	}

	return false
}

func (bc *CaptchaProtect) trippedRateLimit(ip string) bool {
	v, ok := bc.rateCache.Get(ip)
	if !ok {
		bc.log.Error("IP not found, but should already be set", "ip", ip)
		return false
	}
	return v.(uint) > bc.config.RateLimit
}

func (bc *CaptchaProtect) registerRequest(ip string) {
	err := bc.rateCache.Add(ip, uint(1), lru.DefaultExpiration)
	if err == nil {
		return
	}

	_, err = bc.rateCache.IncrementUint(ip, uint(1))
	if err != nil {
		bc.log.Error("unable to set rate cache", "ip", ip, "err", err)
	}
}

func (bc *CaptchaProtect) getClientIP(req *http.Request) (string, string) {
	ip := req.Header.Get(bc.config.IPForwardedHeader)
	if bc.config.IPForwardedHeader != "" && ip != "" {
		components := strings.Split(ip, ",")
		depth := bc.config.IPDepth
		ip = ""
		for i := len(components) - 1; i >= 0; i-- {
			_ip := strings.TrimSpace(components[i])
			if helper.IsIpExcluded(_ip, bc.exemptIps) {
				continue
			}
			if depth == 0 {
				ip = _ip
				break
			}
			depth--
		}
		if ip == "" {
			bc.log.Debug("No non-exempt IPs in header. req.RemoteAddr", "ipDepth", bc.config.IPDepth, bc.config.IPForwardedHeader, req.Header.Get(bc.config.IPForwardedHeader))
			ip = req.RemoteAddr
		}
	} else {
		if bc.config.IPForwardedHeader != "" {
			bc.log.Debug("Received a blank header value. Defaulting to real IP")
		}
		ip = req.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		host, _, err := net.SplitHostPort(ip)
		if err != nil {
			bc.log.Warn("Failed to parse port from IP", "ip", ip, "err", err)
		} else {
			ip = host
		}
	}

	return bc.ParseIp(ip)
}

func (bc *CaptchaProtect) ParseIp(ip string) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip, ip
	}

	// For IPv4 addresses
	if parsedIP.To4() != nil {
		subnet := parsedIP.Mask(bc.ipv4Mask)
		return ip, subnet.String()
	}

	// For IPv6 addresses
	if parsedIP.To16() != nil {
		subnet := parsedIP.Mask(bc.ipv6Mask)
		return ip, subnet.String()
	}

	bc.log.Warn("Unknown ip version", "ip", ip)

	return ip, ip
}

func (bc *CaptchaProtect) SetIpv4Mask(m int) error {
	if m < 8 || m > 32 {
		return fmt.Errorf("invalid ipv4 mask: %d. Must be between 8 and 32", m)
	}
	bc.ipv4Mask = net.CIDRMask(m, 32)

	return nil
}

func (bc *CaptchaProtect) SetIpv6Mask(m int) error {
	if m < 8 || m > 128 {
		return fmt.Errorf("invalid ipv6 mask: %d. Must be between 8 and 128", m)
	}
	bc.ipv6Mask = net.CIDRMask(m, 128)

	return nil
}

func (bc *CaptchaProtect) isGoodBot(req *http.Request, clientIP string) bool {
	if bc.config.ProtectParameters == "true" {
		if len(req.URL.Query()) > 0 {
			return false
		}
	}

	bot, ok := bc.botCache.Get(clientIP)
	if ok {
		return bot.(bool)
	}
	v := false
	if bc.config.EnableGooglebotIPCheck == "true" {
		slog.Debug("Checking if a google IP")
		ip := net.ParseIP(clientIP)
		if ip != nil {
			v = bc.googlebotIPs.Contains(ip)
		}
	}
	if !v {
		v = helper.IsIpGoodBot(clientIP, bc.config.GoodBots)
	}
	bc.botCache.Set(clientIP, v, lru.DefaultExpiration)
	return v
}

func (bc *CaptchaProtect) SetExemptIps(exemptIps []*net.IPNet) {
	bc.exemptIps = exemptIps
}

// ParseHttpMethods logs a warning if protected methods contains an invalid method.
// Note: This method is called during initialization, validation is informational only.
func (c *Config) ParseHttpMethods(log *slog.Logger) {
	for _, method := range c.ProtectHttpMethods {
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE":
			continue
		default:
			log.Warn("Unknown HTTP method", "method", method)
		}
	}
}

func (bc *CaptchaProtect) saveState(ctx context.Context) {
	// Add random jitter to prevent multiple instances from trying to save simultaneously
	jitter := time.Duration(rand.Intn(int(StateSaveJitter.Milliseconds()))) * time.Millisecond
	interval := StateSaveInterval + jitter

	bc.log.Debug("State save configured", "baseInterval", StateSaveInterval, "jitter", jitter, "actualInterval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	file, err := os.OpenFile(bc.config.PersistentStateFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		bc.log.Error("unable to save state, could not open or create file", "stateFile", bc.config.PersistentStateFile, "err", err)
		return
	}
	// we made sure the file is writable, we can continue in our loop
	file.Close()

	for {
		select {
		case <-ticker.C:
			bc.log.Debug("Periodic state save triggered")
			bc.saveStateNow()

		case <-ctx.Done():
			bc.log.Debug("Context cancelled, running saveState before shutdown")
			bc.saveStateNow()
			return
		}
	}
}

// saveStateNow performs an immediate state save using the state package.
func (bc *CaptchaProtect) saveStateNow() {
	reconcile := bc.config.EnableStateReconciliation == "true"

	lockMs, readMs, reconcileMs, marshalMs, writeMs, totalMs, err := state.SaveStateToFile(
		bc.config.PersistentStateFile,
		reconcile,
		bc.rateCache,
		bc.botCache,
		bc.verifiedCache,
		bc.log,
	)

	if err != nil {
		bc.log.Error("failed to save state", "err", err)
		return
	}

	// Get current state for logging (already marshaled in SaveStateToFile, but we need counts)
	currentState := state.GetState(bc.rateCache.Items(), bc.botCache.Items(), bc.verifiedCache.Items())
	bc.log.Debug("State saved successfully",
		"rateEntries", len(currentState.Rate),
		"botEntries", len(currentState.Bots),
		"verifiedEntries", len(currentState.Verified),
		"lockMs", lockMs,
		"readMs", readMs,
		"reconcileMs", reconcileMs,
		"marshalMs", marshalMs,
		"writeMs", writeMs,
		"totalMs", totalMs,
	)
}

func (bc *CaptchaProtect) loadState() {
	err := state.LoadStateFromFile(
		bc.config.PersistentStateFile,
		bc.rateCache,
		bc.botCache,
		bc.verifiedCache,
	)

	if err != nil {
		bc.log.Warn("failed to load state file", "err", err)
		return
	}

	bc.log.Info("Loaded previous state")
}

func (bc *CaptchaProtect) ChallengeOnPage() bool {
	return bc.config.ChallengeURL == "?challenge=true"
}
