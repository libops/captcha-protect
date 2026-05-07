package captcha_protect

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/libops/captcha-protect/internal/helper"
	lru "github.com/patrickmn/go-cache"
)

const ciRateLimit = uint(5)
const ciRootSmokeIP = "192.0.2.10"
const ciApp2SmokeIP = "198.51.100.10"

func TestCILabelEquivalentMiddlewareBehavior(t *testing.T) {
	bc := newCILabelEquivalentMiddleware(t, nil)

	for i := uint(0); i < ciRateLimit; i++ {
		assertNoRedirect(t, bc, ciRootSmokeIP, "/")
	}
	assertRedirect(t, bc, ciRootSmokeIP, "/", "/challenge?destination=%2F")

	for _, route := range []string{
		"/node/123/manifest",
		"/node/123/book-manifest",
		"/oai/request?foo=bar",
	} {
		assertNoRedirect(t, bc, ciRootSmokeIP, route)
	}

	for i := uint(0); i < ciRateLimit; i++ {
		assertNoRedirect(t, bc, ciApp2SmokeIP, "/app2")
	}
	assertRedirect(t, bc, ciApp2SmokeIP, "/app2", "/challenge?destination=%2Fapp2")
}

func TestCILabelEquivalentGooglebotParameterBehavior(t *testing.T) {
	googleIP := "203.0.113.10"

	bypass := newCILabelEquivalentMiddleware(t, nil)
	bypass.googlebotIPs = helper.NewGooglebotIPs()
	bypass.googlebotIPs.Update([]string{"203.0.113.0/24"}, discardLogger())
	bypass.config.EnableGooglebotIPCheck = "true"

	for i := uint(0); i < ciRateLimit+1; i++ {
		assertNoRedirect(t, bypass, googleIP, "/")
	}

	protectedParams := newCILabelEquivalentMiddleware(t, func(config *Config) {
		config.ProtectParameters = "true"
	})
	protectedParams.googlebotIPs = helper.NewGooglebotIPs()
	protectedParams.googlebotIPs.Update([]string{"203.0.113.0/24"}, discardLogger())
	protectedParams.config.EnableGooglebotIPCheck = "true"

	for i := uint(0); i < ciRateLimit; i++ {
		assertNoRedirect(t, protectedParams, googleIP, "/?foo=bar")
	}
	assertRedirect(t, protectedParams, googleIP, "/?foo=bar", "/challenge?destination=%2F%3Ffoo%3Dbar")
}

func TestPersistentStateSharingWithSynctest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stateFile := filepath.Join(t.TempDir(), "state.json")
		writer := newStateOnlyCaptchaProtect(stateFile, 2)
		reader := newStateOnlyCaptchaProtect(stateFile, 2)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{}, 1)
		go func() {
			writer.saveState(ctx)
			done <- struct{}{}
		}()

		for i := uint(0); i < writer.config.RateLimit+1; i++ {
			writer.registerRequest("192.0.0.0")
		}

		time.Sleep(stateSaveInterval(writer.config) + StateSaveJitter + 3*time.Second)
		synctest.Wait()
		reader.reconcileStateFromFileIfChanged()

		v, ok := reader.rateCache.Get("192.0.0.0")
		if !ok {
			t.Fatal("expected reader instance to reconcile writer state")
		}
		if got, want := v.(uint), writer.config.RateLimit+1; got != want {
			t.Fatalf("reconciled rate = %d, want %d", got, want)
		}

		cancel()
		synctest.Wait()
		<-done
	})
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
	config.RateLimit = ciRateLimit
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
	config.Mode = "regex"
	config.ProtectRoutes = []string{"^/"}
	config.ExcludeRoutes = []string{
		`\/oai\/request`,
		`\/node\/\d+\/(book-)?manifest`,
	}
	return config
}

func newStateOnlyCaptchaProtect(stateFile string, rateLimit uint) *CaptchaProtect {
	config := ciLabelEquivalentConfig()
	config.PersistentStateFile = stateFile
	config.EnableStateReconciliation = "true"
	config.RateLimit = rateLimit

	return &CaptchaProtect{
		config:        config,
		log:           discardLogger(),
		rateCache:     lru.New(time.Hour, lru.NoExpiration),
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
