package captcha_protect

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libops/captcha-protect/internal/helper"
	lru "github.com/patrickmn/go-cache"
)

const ciRootSmokeIP = "192.0.2.10"
const ciApp2SmokeIP = "198.51.100.10"

func TestCILabelEquivalentMiddlewareBehavior(t *testing.T) {
	bc := newCILabelEquivalentMiddleware(t, nil)

	assertRedirect(t, bc, ciRootSmokeIP, "/", "/challenge?destination=%2F")

	for _, route := range []string{
		"/node/123/manifest",
		"/node/123/book-manifest",
		"/oai/request?foo=bar",
	} {
		assertNoRedirect(t, bc, ciRootSmokeIP, route)
	}

	assertRedirect(t, bc, ciApp2SmokeIP, "/app2", "/challenge?destination=%2Fapp2")
}

func TestCILabelEquivalentGooglebotParameterBehavior(t *testing.T) {
	googleIP := "203.0.113.10"

	bypass := newCILabelEquivalentMiddleware(t, nil)
	bypass.googlebotIPs = helper.NewGooglebotIPs()
	bypass.googlebotIPs.Update([]string{"203.0.113.0/24"}, discardLogger())
	bypass.config.EnableGooglebotIPCheck = "true"

	assertNoRedirect(t, bypass, googleIP, "/")

	protectedParams := newCILabelEquivalentMiddleware(t, func(config *Config) {
		config.ProtectParameters = "true"
	})
	protectedParams.googlebotIPs = helper.NewGooglebotIPs()
	protectedParams.googlebotIPs.Update([]string{"203.0.113.0/24"}, discardLogger())
	protectedParams.config.EnableGooglebotIPCheck = "true"

	assertRedirect(t, protectedParams, googleIP, "/?foo=bar", "/challenge?destination=%2F%3Ffoo%3Dbar")
}

func TestCILabelEquivalentUptimeRobotBypassBehavior(t *testing.T) {
	uptimeRobotIP := "203.0.113.10"

	bypass := newCILabelEquivalentMiddleware(t, nil)
	bypass.uptimeRobotIPs = helper.NewUptimeRobotIPs()
	bypass.uptimeRobotIPs.Update([]string{"203.0.113.10/32"}, discardLogger())
	bypass.config.EnableUptimeRobotBypass = "true"

	assertNoRedirect(t, bypass, uptimeRobotIP, "/")

	disabled := newCILabelEquivalentMiddleware(t, nil)
	disabled.uptimeRobotIPs = helper.NewUptimeRobotIPs()
	disabled.uptimeRobotIPs.Update([]string{"203.0.113.10/32"}, discardLogger())
	assertRedirect(t, disabled, uptimeRobotIP, "/", "/challenge?destination=%2F")
}

func newCILabelEquivalentMiddleware(t *testing.T, mutate func(*Config)) *CaptchaProtect {
	t.Helper()

	config := ciLabelEquivalentConfig()
	if mutate != nil {
		mutate(config)
	}

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})
	bc, err := NewCaptchaProtect(t.Context(), next, config, "captcha-protect")
	if err != nil {
		t.Fatalf("NewCaptchaProtect failed: %v", err)
	}

	return bc
}

func ciLabelEquivalentConfig() *Config {
	config := CreateConfig()
	config.Window = 120
	config.CaptchaProvider = "poj"
	config.SiteKey = "test-site-key"
	config.SecretKey = "test-secret-key"
	config.EnableStatsPage = "true"
	config.IPForwardedHeader = "X-Forwarded-For"
	config.LogLevel = "ERROR"
	config.ProtectParameters = "false"
	config.GoodBots = []string{}
	config.EnableGooglebotIPCheck = "false"
	config.EnableUptimeRobotBypass = "false"
	config.Mode = "regex"
	config.ProtectRoutes = []string{"^/"}
	config.ExcludeRoutes = []string{
		`\/oai\/request`,
		`\/node\/\d+\/(book-)?manifest`,
	}
	return config
}

func newStateOnlyCaptchaProtect(stateFile string) *CaptchaProtect {
	config := ciLabelEquivalentConfig()
	config.PersistentStateFile = stateFile

	return &CaptchaProtect{
		config:        config,
		log:           discardLogger(),
		botCache:      lru.New(time.Hour, lru.NoExpiration),
		verifiedCache: lru.New(time.Hour, lru.NoExpiration),
	}
}

func assertNoRedirect(t *testing.T, handler http.Handler, ip, target string) {
	t.Helper()

	status, location := serveCITestRequest(handler, ip, target)
	if location != "" {
		t.Fatalf("%s returned redirect %q", target, location)
	}
	if status != http.StatusNoContent {
		t.Fatalf("%s status = %d, want %d", target, status, http.StatusNoContent)
	}
}

func assertRedirect(t *testing.T, handler http.Handler, ip, target, expectedLocation string) {
	t.Helper()

	status, location := serveCITestRequest(handler, ip, target)
	if status != http.StatusFound {
		t.Fatalf("%s status = %d, want %d", target, status, http.StatusFound)
	}
	if location != expectedLocation {
		t.Fatalf("%s redirect = %q, want %q", target, location, expectedLocation)
	}
}

func serveCITestRequest(handler http.Handler, ip, target string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "localhost"
	req.Header.Set("X-Forwarded-For", ip)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	return rw.Code, rw.Header().Get("Location")
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
