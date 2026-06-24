package captcha_protect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/libops/captcha-protect/internal/helper"
)

func TestRouteIsProtected(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		path     string
		expected bool
	}{
		{
			name: "Protected route - exact match",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/baz",
			expected: true,
		},
		{
			name: "Unprotected route",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/ddos-me",
			expected: false,
		},
		{
			name: "Protected route with included file extension",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{"jp2", "json"},
				ExcludeRoutes:         []string{},
			},
			path:     "/foo/bar/style.json",
			expected: true,
		},
		{
			name: "html always protected",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{"jp2", "json"},
				ExcludeRoutes:         []string{},
			},
			path:     "/foo/bar/data.html",
			expected: true,
		},
		{
			name: "subpath route protection",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/bar/any/route",
			expected: true,
		},
		{
			name: "File extension in unprotected route",
			config: Config{
				ProtectRoutes:         []string{"/foo", "/bar", "/baz"},
				ProtectFileExtensions: []string{"jp2", "json"},
				ExcludeRoutes:         []string{},
			},
			path:     "/unprotected/script.json",
			expected: false,
		},
		{
			name: "Excluded route not protected (exact match)",
			config: Config{
				ProtectRoutes:         []string{"/"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{"/ajax"},
			},
			path:     "/ajax",
			expected: false,
		},
		{
			name: "Excluded route not protected (prefix match)",
			config: Config{
				ProtectRoutes:         []string{"/foo"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{"/ajax"},
			},
			path:     "/ajax/foo",
			expected: false,
		},
		{
			name: "Excluded route protected (no prefix match)",
			config: Config{
				ProtectRoutes:         []string{"/"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{"/ajax"},
			},
			path:     "/not-ajax",
			expected: true,
		},
	}

	for _, tt := range tests {
		for _, useRegex := range []bool{false, true} {
			mode := "prefix"
			if useRegex {
				mode = "regex"
			}

			t.Run(tt.name+"_"+mode, func(t *testing.T) {
				c := CreateConfig()
				c.Mode = mode
				c.SiteKey = "test-site-key"
				c.SecretKey = "test-secret-key"
				c.ProtectFileExtensions = append(c.ProtectFileExtensions, tt.config.ProtectFileExtensions...)

				if useRegex {
					// Convert each route to ^... regex for "HasPrefix" behavior
					for _, route := range tt.config.ProtectRoutes {
						c.ProtectRoutes = append(c.ProtectRoutes, "^"+regexp.QuoteMeta(route))
					}
					for _, exclude := range tt.config.ExcludeRoutes {
						c.ExcludeRoutes = append(c.ExcludeRoutes, "^"+regexp.QuoteMeta(exclude))
					}
				} else {
					c.ProtectRoutes = append(c.ProtectRoutes, tt.config.ProtectRoutes...)
					c.ExcludeRoutes = append(c.ExcludeRoutes, tt.config.ExcludeRoutes...)
				}

				bc, err := NewCaptchaProtect(context.Background(), nil, c, "captcha-protect")
				if err != nil {
					t.Errorf("unexpected error %v", err)
				}

				if useRegex {
					result := bc.RouteIsProtectedRegex(tt.path)
					if result != tt.expected {
						t.Errorf("RouteIsProtected(%q) = %v; want %v (mode: %s)", tt.path, result, tt.expected, mode)
					}
				} else {
					result := bc.RouteIsProtectedPrefix(tt.path)
					if result != tt.expected {
						t.Errorf("RouteIsProtected(%q) = %v; want %v (mode: %s)", tt.path, result, tt.expected, mode)
					}
				}
			})
		}
	}

}

func TestRouteIsProtectedSuffix(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		path     string
		expected bool
	}{
		{
			name: "Protected route - suffix match",
			config: Config{
				ProtectRoutes:         []string{"baz"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/baz",
			expected: true,
		},
		{
			name: "Unprotected route - no suffix match",
			config: Config{
				ProtectRoutes:         []string{"baz"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/foo/bar",
			expected: false,
		},
		{
			name: "Protected route with file extension",
			config: Config{
				ProtectRoutes:         []string{"style"},
				ProtectFileExtensions: []string{"json"},
				ExcludeRoutes:         []string{},
			},
			path:     "/foo/bar/style.json",
			expected: true,
		},
		{
			name: "Protected by extension only",
			config: Config{
				ProtectRoutes:         []string{"index"},
				ProtectFileExtensions: []string{"html"},
				ExcludeRoutes:         []string{},
			},
			path:     "/whatever/index.html",
			expected: true,
		},
		{
			name: "Suffix protected route",
			config: Config{
				ProtectRoutes:         []string{"route"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{},
			},
			path:     "/bar/any/route",
			expected: true,
		},
		{
			name: "Excluded route - suffix match",
			config: Config{
				ProtectRoutes:         []string{"ajax"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{"/api"},
			},
			path:     "/api/ajax",
			expected: false,
		},
		{
			name: "Protected route - not excluded",
			config: Config{
				ProtectRoutes:         []string{"ajax"},
				ProtectFileExtensions: []string{},
				ExcludeRoutes:         []string{"notajax"},
			},
			path:     "/real/ajax",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CreateConfig()
			c.SiteKey = "test-site-key"
			c.SecretKey = "test-secret-key"
			c.ProtectRoutes = append(c.ProtectRoutes, tt.config.ProtectRoutes...)
			c.ExcludeRoutes = append(c.ExcludeRoutes, tt.config.ExcludeRoutes...)
			c.Mode = "suffix"
			c.ProtectFileExtensions = append(c.ProtectFileExtensions, tt.config.ProtectFileExtensions...)
			bc, err := NewCaptchaProtect(context.Background(), nil, c, "captcha-protect")
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}

			result := bc.RouteIsProtectedSuffix(tt.path)
			if result != tt.expected {
				t.Errorf("RouteIsProtectedSuffix(%q) = %v; want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		headerValue string
		remoteAddr  string
		expectedIP  string
	}{
		{
			name: "Header with multiple IPs, no exclusion, IPDepth 0 picks last IP",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           0,
			},
			headerValue: "1.1.1.1, 2.2.2.2",
			remoteAddr:  "3.3.3.3:1234",
			expectedIP:  "2.2.2.2",
		},
		{
			name: "Header with multiple IPs and one excluded, IPDepth 0 picks non-excluded last",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           0,
				ExemptIPs:         []string{"2.2.2.2/32"},
			},
			headerValue: "1.1.1.1, 3.3.3.3, 2.2.2.2",
			remoteAddr:  "3.3.3.3:1234",
			expectedIP:  "3.3.3.3",
		},
		{
			name: "Header with multiple IPs, IPDepth 1 picks second-to-last non-exempt IP",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           1,
			},
			headerValue: "1.1.1.1, 2.2.2.2, 3.3.3.3, 127.0.0.1, 192.168.0.1",
			remoteAddr:  "3.3.3.3:1234",
			expectedIP:  "2.2.2.2",
		},
		{
			name: "Header with multiple IPs, IPDepth 1 picks second-to-last IP",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           1,
			},
			headerValue: "1.1.1.1, 2.2.2.2, 3.3.3.3",
			remoteAddr:  "3.3.3.3:1234",
			expectedIP:  "2.2.2.2",
		},
		{
			name: "Header with just exempt IPs header falls back to RemoteAddr with port stripped",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           0,
				ExemptIPs:         []string{"2.2.0.0/16"},
			},
			headerValue: "127.0.0.1, 192.168.1.1, 172.16.1.2, 2.2.3.4",
			remoteAddr:  "4.4.4.4:5678",
			expectedIP:  "4.4.4.4",
		},
		{
			name: "Blank header falls back to RemoteAddr with port stripped",
			config: Config{
				IPForwardedHeader: "X-Forwarded-For",
				IPDepth:           0,
			},
			headerValue: "",
			remoteAddr:  "4.4.4.4:5678",
			expectedIP:  "4.4.4.4",
		},
		{
			name: "Header not set in config, use RemoteAddr",
			config: Config{
				IPDepth:           0,
				IPForwardedHeader: "",
			},
			headerValue: "shouldBeIgnored",
			remoteAddr:  "5.5.5.5:4321",
			expectedIP:  "5.5.5.5",
		},
	}
	for _, tc := range tests {

		t.Run(tc.name, func(t *testing.T) {
			// Create a dummy request
			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.Header.Set("X-Forwarded-For", tc.headerValue)

			req.RemoteAddr = tc.remoteAddr

			c := CreateConfig()
			c.SiteKey = "test-site-key"
			c.SecretKey = "test-secret-key"
			c.IPForwardedHeader = tc.config.IPForwardedHeader
			c.IPDepth = tc.config.IPDepth
			c.ProtectRoutes = []string{"/"}
			c.ExemptIPs = tc.config.ExemptIPs
			bc, err := NewCaptchaProtect(context.Background(), nil, c, "captcha-protect")
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}

			ip := bc.getClientIP(req)
			if ip != tc.expectedIP {
				t.Errorf("expected ip %s, got %s", tc.expectedIP, ip)
			}
		})
	}
}

func TestServeHTTP(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, err := rw.Write([]byte("next"))
		if err != nil {
			slog.Error("problems", "err", err)
			os.Exit(1)
		}
	})
	config := CreateConfig()
	tests := []struct {
		name           string
		expectedStatus uint
		challengePage  string
		expectedBody   string
		challengeCode  int
	}{
		{
			name:           "Redirect to 302",
			challengePage:  "/challenge",
			expectedStatus: http.StatusFound,
			expectedBody:   "/challenge?destination=%2Fsomepath",
			challengeCode:  http.StatusOK,
		},
		{
			name:           "403 when changing default challenge code",
			challengePage:  "/challenge",
			expectedStatus: http.StatusFound,
			challengeCode:  http.StatusForbidden,
			expectedBody:   "/challenge?destination=%2Fsomepath",
		},
		{
			name:           "429 when challenging on same page",
			challengePage:  "",
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   "One moment while we verify your network connection",
			challengeCode:  http.StatusTooManyRequests,
		},
		{
			name:           "403 when challenging on same page",
			challengePage:  "",
			expectedStatus: http.StatusForbidden,
			challengeCode:  http.StatusForbidden,
			expectedBody:   "One moment while we verify your network connection",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config.SiteKey = "test-site-key"
			config.SecretKey = "test-secret-key"
			config.CaptchaProvider = "turnstile"
			config.ProtectRoutes = []string{"/"}
			config.ChallengeURL = tc.challengePage
			config.ChallengeStatusCode = tc.challengeCode
			config.ExemptIPs = []string{}
			cp, err := NewCaptchaProtect(context.Background(), next, config, "captcha-protect")
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/somepath", nil)
			req.RequestURI = "/somepath"
			rr := httptest.NewRecorder()
			cp.ServeHTTP(rr, req)
			if rr.Code != int(tc.expectedStatus) {
				t.Errorf("expected %d got %d", tc.expectedStatus, rr.Code)
			}
			body := rr.Body.String()
			if !strings.Contains(body, tc.expectedBody) {
				t.Errorf("expected %s got %s", tc.expectedBody, body)
			}

			// we're done testing if challenging on same page
			if tc.challengePage == "" {
				return
			}

			// if redirecting, test the /challenge page
			// and ensure it returns the status we set
			req = httptest.NewRequest(http.MethodGet, "http://example.com"+tc.challengePage, nil)
			req.RequestURI = tc.challengePage
			rr = httptest.NewRecorder()
			cp.ServeHTTP(rr, req)
			if rr.Code != int(tc.challengeCode) {
				t.Errorf("expected %d got %d", tc.challengeCode, rr.Code)
			}
		})
	}
}

func TestServeHTTPAllowsGoodBotOnFirstRequest(t *testing.T) {
	upstreamCalled := false
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		upstreamCalled = true
		rw.WriteHeader(http.StatusOK)
	})
	config := CreateConfig()
	config.SiteKey = "test-site-key"
	config.SecretKey = "test-secret-key"
	config.ProtectRoutes = []string{"/"}
	config.GoodBots = []string{"yandex.com"}

	cp, err := NewCaptchaProtect(context.Background(), next, config, "captcha-protect")
	if err != nil {
		t.Fatal(err)
	}
	lookupCalled := false
	cp.goodBotLookup = func(ctx context.Context, clientIP string, goodBots []string) bool {
		lookupCalled = true
		if _, ok := ctx.Deadline(); !ok {
			t.Error("expected DNS lookup context to have a deadline")
		}
		return clientIP == "5.255.231.189" && len(goodBots) == 1 && goodBots[0] == "yandex.com"
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "5.255.231.189:1234"
	rw := httptest.NewRecorder()
	cp.ServeHTTP(rw, req)

	if !lookupCalled {
		t.Fatal("expected DNS verification on the first request")
	}
	if !upstreamCalled {
		t.Fatal("expected verified bot's first request to reach the upstream handler")
	}
	if rw.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rw.Code)
	}
}

func TestIsGoodUserAgent(t *testing.T) {
	tests := []struct {
		name             string
		exemptUserAgents []string
		ua               string
		expected         bool
	}{
		{"Matching first substring", []string{"Mozilla", "Google"}, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", true},
		{"Matching second substring", []string{"Bing", "Edge"}, "Edge/12.0", true},
		{"Matching substring within user agent", []string{"YandexBot"}, "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", true},
		{"Case insensitive", []string{"bing", "Edge"}, "BING/12.0", true},
		{"No matching substring", []string{"Mozilla", "Google"}, "Safari/537.36", false},
		{"Empty user agent", []string{"Mozilla", "Google"}, "", false},
		{"Empty exempt list", []string{}, "Mozilla/5.0", false},
	}
	config := CreateConfig()
	config.SiteKey = "test-site-key"
	config.SecretKey = "test-secret-key"
	config.ProtectRoutes = []string{"/"}
	for _, tc := range tests {
		config.ExemptUserAgents = tc.exemptUserAgents
		cp, err := NewCaptchaProtect(context.Background(), nil, config, "captcha-protect")
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		got := cp.isGoodUserAgent(tc.ua)
		if got != tc.expected {
			t.Errorf("%s: expected %v, got %v", tc.name, tc.expected, got)
		}
	}
}

func TestNewCaptchaProtectValidation(t *testing.T) {
	tests := []struct {
		name         string
		modifyConfig func(*Config)
		expectError  string
	}{
		{
			name:         "Missing SiteKey",
			modifyConfig: func(c *Config) { c.SiteKey = "" },
			expectError:  "siteKey is required",
		},
		{
			name:         "Missing SecretKey",
			modifyConfig: func(c *Config) { c.SecretKey = "" },
			expectError:  "secretKey is required",
		},
		{
			name:         "Zero Window",
			modifyConfig: func(c *Config) { c.Window = 0 },
			expectError:  "window must be positive",
		},
		{
			name:         "Negative Window",
			modifyConfig: func(c *Config) { c.Window = -1 },
			expectError:  "window must be positive",
		},
		{
			name:         "Invalid CAPTCHA Provider",
			modifyConfig: func(c *Config) { c.CaptchaProvider = "invalid" },
			expectError:  "invalid captcha provider",
		},
		{
			name: "Invalid regex in ProtectRoutes",
			modifyConfig: func(c *Config) {
				c.Mode = "regex"
				c.ProtectRoutes = []string{"[invalid"}
			},
			expectError: "invalid regex in protectRoutes",
		},
		{
			name: "Invalid regex in ExcludeRoutes",
			modifyConfig: func(c *Config) {
				c.Mode = "regex"
				c.ExcludeRoutes = []string{"[invalid"}
			},
			expectError: "invalid regex in excludeRoutes",
		},
		{
			name:         "ChallengeURL is /",
			modifyConfig: func(c *Config) { c.ChallengeURL = "/" },
			expectError:  "challenge URL can not be the entire site",
		},
		{
			name:         "Invalid mode",
			modifyConfig: func(c *Config) { c.Mode = "invalid" },
			expectError:  "unknown mode",
		},
		{
			name: "Invalid CIDR in ExemptIPs",
			modifyConfig: func(c *Config) {
				c.ExemptIPs = []string{"not-a-cidr"}
			},
			expectError: "error parsing cidr",
		},
		{
			name:         "No protected routes in prefix mode",
			modifyConfig: func(c *Config) { c.ProtectRoutes = []string{} },
			expectError:  "you must protect at least one route",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CreateConfig()
			c.SiteKey = "test"
			c.SecretKey = "test"
			c.ProtectRoutes = []string{"/"}
			tt.modifyConfig(c)

			_, err := NewCaptchaProtect(context.Background(), nil, c, "test")
			if err == nil {
				t.Errorf("Expected error containing %q, got nil", tt.expectError)
			} else if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("Expected error containing %q, got %q", tt.expectError, err.Error())
			}
		})
	}
}

func TestRedactedConfigDoesNotExposeSecretKey(t *testing.T) {
	config := CreateConfig()
	config.SecretKey = "super-secret"

	redacted := redactedConfig(config)
	if redacted.SecretKey == config.SecretKey {
		t.Fatal("expected secret key to be redacted")
	}
	if redacted.SecretKey != "[REDACTED]" {
		t.Fatalf("unexpected redacted secret value %q", redacted.SecretKey)
	}
	if config.SecretKey != "super-secret" {
		t.Fatal("redactedConfig mutated the original config")
	}
}

func TestIsGoodBotWithParameters(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.ProtectParameters = "true"
	config.GoodBots = []string{"bing.com"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	// Mock bot cache to simulate good bot
	bc.botCache.Set("1.2.3.4", true, 1*time.Hour)

	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"URL without params - good bot allowed", "http://example.com/page", true},
		{"URL with params - good bot blocked", "http://example.com/page?foo=bar", false},
		{"URL with multiple params - good bot blocked", "http://example.com/page?foo=bar&baz=qux", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			result := bc.isGoodBot(req, "1.2.3.4")
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestVerifiedCacheBypasses(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	clientIP := "1.2.3.4"

	// Should apply before verification
	if !bc.shouldApply(req, clientIP) {
		t.Error("Should apply protection before verification")
	}

	// Add to verified cache
	bc.verifiedCache.Set(clientIP, true, 1*time.Hour)

	// Should not apply after verification
	if bc.shouldApply(req, clientIP) {
		t.Error("Should not apply protection after verification")
	}
}

func TestShouldApplyRegexExcludeRoutesIgnoreQueryString(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.Mode = "regex"
	config.ProtectRoutes = []string{"^/"}
	config.ExcludeRoutes = []string{`\/oai\/request`, `\/node\/\d+\/(book-)?manifest`}

	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "query string does not prevent exclude route match",
			url:  "http://example.com/oai/request?foo=bar",
			want: false,
		},
		{
			name: "regex exclude route matches manifest path",
			url:  "http://example.com/node/123/manifest",
			want: false,
		},
		{
			name: "non excluded route still protected",
			url:  "http://example.com/node/123/other",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			if got := bc.shouldApply(req, "1.2.3.4"); got != tt.want {
				t.Errorf("shouldApply(%q) = %v; want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestStatsPage(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.EnableStatsPage = "true"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	bc.verifiedCache.Set("1.2.3.4", true, 1*time.Hour)

	tests := []struct {
		name           string
		clientIP       string
		expectedStatus int
	}{
		{"Exempt IP can access", "192.168.1.1", http.StatusOK},
		{"Private IP can access", "10.0.0.1", http.StatusOK},
		{"Non-exempt IP forbidden", "1.2.3.4", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			bc.serveStatsPage(rr, tt.clientIP)

			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				// Verify JSON response
				var stats map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
					t.Errorf("Failed to parse JSON: %v", err)
				}
				if _, ok := stats["verified"]; !ok {
					t.Error("Stats JSON missing 'verified' key")
				}
			}
		})
	}
}

func TestProtectHttpMethods(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.ProtectHttpMethods = []string{"GET", "POST"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	tests := []struct {
		method   string
		expected bool
	}{
		{"GET", true},
		{"POST", true},
		{"PUT", false},
		{"DELETE", false},
		{"PATCH", false},
		{"HEAD", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://example.com/test", nil)
			result := bc.shouldApply(req, "1.2.3.4")
			if result != tt.expected {
				t.Errorf("Method %s: expected %v, got %v", tt.method, tt.expected, result)
			}
		})
	}
}

func TestIsExtensionProtected(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.ProtectFileExtensions = []string{"html", "php", "json"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	tests := []struct {
		path     string
		expected bool
	}{
		{"/index.html", true},
		{"/api.json", true},
		{"/script.php", true},
		{"/style.css", false},
		{"/image.jpg", false},
		{"/no-extension", true},      // No extension = protected
		{"/path/to/file.HTML", true}, // Case insensitive
		{"/path/to/file.JSON", true},
		{"/path/to/file.Php", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := bc.isExtensionProtected(tt.path)
			if result != tt.expected {
				t.Errorf("Path %s: expected %v, got %v", tt.path, tt.expected, result)
			}
		})
	}
}

func TestStatePersistence(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "state.json")

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	// Manually save state by writing the file directly.
	// This tests restart persistence without relying on the background goroutine.
	futureExpiration := time.Now().Add(1 * time.Hour).UnixNano()
	jsonData, _ := json.Marshal(map[string]interface{}{
		"verified": map[string]map[string]interface{}{
			"1.2.3.4": {
				"value":      true,
				"expiration": float64(futureExpiration),
			},
		},
	})
	err := os.WriteFile(tmpFile, jsonData, 0644)
	if err != nil {
		t.Fatalf("Failed to write state file: %v", err)
	}

	// Create new instance - should load state
	bc2, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc2.loadStateFrom(tmpFile)

	// Check verified cache
	_, found := bc2.verifiedCache.Get("1.2.3.4")
	if !found {
		t.Error("Verified cache state not persisted correctly")
	}

}

func TestStatePersistenceDisabledWithoutStateFile(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Fatalf("NewCaptchaProtect failed: %v", err)
	}

	bc.markStateDirty()

	if bc.currentStateDirty() != 0 {
		t.Fatal("state dirty counter should remain disabled without a persistent state file")
	}
	if bc.hasUnsavedState() {
		t.Fatal("state should not become unsaved without a persistent state file")
	}
}

func TestSaveStateFlushesDirtyStateOnCanceledContext(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "state.json")
	bc := newStateOnlyCaptchaProtect(tmpFile)

	bc.verifiedCache.Set("192.168.0.10", true, time.Hour)
	bc.markStateDirty()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	bc.saveState(ctx)

	if bc.hasUnsavedState() {
		t.Fatal("expected canceled saveState to flush dirty state before returning")
	}

	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("expected state file to be written: %v", err)
	}

	var saved struct {
		Verified map[string]json.RawMessage `json:"verified"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("state file did not contain valid JSON: %v", err)
	}
	if _, ok := saved.Verified["192.168.0.10"]; !ok {
		t.Fatal("expected dirty verified entry to be persisted")
	}
}

func TestSaveStateNowReturnsFalseAndKeepsDirtyStateOnWriteError(t *testing.T) {
	statePath := t.TempDir()
	bc := newStateOnlyCaptchaProtect(statePath)
	bc.verifiedCache.Set("192.168.0.10", true, time.Hour)
	bc.markStateDirty()

	if bc.saveStateNow() {
		t.Fatal("expected saveStateNow to fail when persistent state path is a directory")
	}
	if !bc.hasUnsavedState() {
		t.Fatal("expected failed save to keep state dirty")
	}
}

func TestStateBookkeepingCounters(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing", "state.json")
	bc := newStateOnlyCaptchaProtect(missingFile)

	bc.stateMu.Lock()
	bc.stateDirty = 1
	bc.stateSavedDirty = 2
	bc.stateMu.Unlock()
	if got := bc.unsavedStateChanges(); got != 0 {
		t.Fatalf("unsavedStateChanges with saved counter ahead = %d, want 0", got)
	}
}

func TestVerifyChallengePage(t *testing.T) {
	validChallengeTS := time.Now().Add(-1 * time.Minute).Format(time.RFC3339Nano)
	validCaptchaResponse := fmt.Sprintf(`{"success":true,"hostname":"example.com","challenge_ts":%q}`, validChallengeTS)

	tests := []struct {
		name             string
		provider         string
		formValues       map[string]string
		mockResponse     string
		expectedStatus   int
		shouldSetCache   bool
		expectedLocation string
	}{
		{
			name:           "Missing captcha response",
			provider:       "turnstile",
			formValues:     map[string]string{},
			expectedStatus: http.StatusBadRequest,
			shouldSetCache: false,
		},
		{
			name:     "Successful verification with destination",
			provider: "turnstile",
			formValues: map[string]string{
				"cf-turnstile-response": "valid-token",
				"destination":           "%2Fhome",
			},
			mockResponse:     validCaptchaResponse,
			expectedStatus:   http.StatusFound,
			shouldSetCache:   true,
			expectedLocation: "/home",
		},
		{
			name:     "Successful verification preserves literal plus",
			provider: "turnstile",
			formValues: map[string]string{
				"cf-turnstile-response": "valid-token",
				"destination":           "/Chrome%20+%20MariaDB%20",
			},
			mockResponse:     validCaptchaResponse,
			expectedStatus:   http.StatusFound,
			shouldSetCache:   true,
			expectedLocation: "/Chrome%20+%20MariaDB%20",
		},
		{
			name:     "Successful verification without destination",
			provider: "recaptcha",
			formValues: map[string]string{
				"g-recaptcha-response": "valid-token",
			},
			mockResponse:     `{"success":true}`,
			expectedStatus:   http.StatusFound,
			shouldSetCache:   true,
			expectedLocation: "/",
		},
		{
			name:     "Failed verification",
			provider: "hcaptcha",
			formValues: map[string]string{
				"h-captcha-response": "invalid-token",
			},
			mockResponse:   `{"success":false}`,
			expectedStatus: http.StatusForbidden,
			shouldSetCache: false,
		},
		{
			name:     "Invalid destination URL",
			provider: "turnstile",
			formValues: map[string]string{
				"cf-turnstile-response": "valid-token",
				"destination":           "%ZZ",
			},
			mockResponse:     validCaptchaResponse,
			expectedStatus:   http.StatusFound,
			shouldSetCache:   true,
			expectedLocation: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.mockResponse))
			}))
			defer mockServer.Close()

			config := CreateConfig()
			config.SiteKey = "test"
			config.SecretKey = "test"
			config.ProtectRoutes = []string{"/"}
			config.CaptchaProvider = tt.provider

			bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

			// Override the validation URL to point to our mock server
			bc.captchaConfig.validate = mockServer.URL

			// Create request with form values
			req := httptest.NewRequest("POST", "http://example.com/challenge", nil)
			req.Form = make(map[string][]string)
			for k, v := range tt.formValues {
				req.Form.Set(k, v)
			}

			rr := httptest.NewRecorder()
			clientIP := "1.2.3.4"

			status := bc.verifyChallengePage(rr, req, clientIP)

			if status != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, status)
			}

			// Check if IP was added to verified cache
			_, found := bc.verifiedCache.Get(clientIP)
			if found != tt.shouldSetCache {
				t.Errorf("Expected cache set=%v, got=%v", tt.shouldSetCache, found)
			}

			if tt.expectedLocation != "" && rr.Header().Get("Location") != tt.expectedLocation {
				t.Errorf("Expected Location %q, got %q", tt.expectedLocation, rr.Header().Get("Location"))
			}
		})
	}
}

func TestVerifyChallengePageRejectsInvalidSiteverifyMetadata(t *testing.T) {
	tests := []struct {
		name         string
		mockResponse string
	}{
		{
			name:         "success false",
			mockResponse: fmt.Sprintf(`{"success":false,"hostname":"example.com","challenge_ts":%q}`, time.Now().Format(time.RFC3339Nano)),
		},
		{
			name:         "hostname mismatch",
			mockResponse: fmt.Sprintf(`{"success":true,"hostname":"evil.example","challenge_ts":%q}`, time.Now().Format(time.RFC3339Nano)),
		},
		{
			name:         "stale challenge",
			mockResponse: fmt.Sprintf(`{"success":true,"hostname":"example.com","challenge_ts":%q}`, time.Now().Add(-6*time.Minute).Format(time.RFC3339Nano)),
		},
		{
			name:         "missing challenge timestamp",
			mockResponse: `{"success":true,"hostname":"example.com"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.mockResponse))
			}))
			defer mockServer.Close()

			config := CreateConfig()
			config.SiteKey = "test"
			config.SecretKey = "test"
			config.ProtectRoutes = []string{"/"}
			config.CaptchaProvider = "turnstile"

			bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
			bc.captchaConfig.validate = mockServer.URL

			req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", nil)
			req.Form = make(map[string][]string)
			req.Form.Set("cf-turnstile-response", "token-"+tt.name)

			rr := httptest.NewRecorder()
			status := bc.verifyChallengePage(rr, req, "1.2.3.4")

			if status != http.StatusForbidden {
				t.Fatalf("expected status %d, got %d", http.StatusForbidden, status)
			}
			if _, found := bc.verifiedCache.Get("1.2.3.4"); found {
				t.Fatal("did not expect invalid siteverify response to set verified cache")
			}
		})
	}
}

func TestVerifyChallengePageAllowsNonTurnstileWithoutMetadata(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer mockServer.Close()

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "hcaptcha"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc.captchaConfig.validate = mockServer.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("h-captcha-response", "valid-token")

	rr := httptest.NewRecorder()
	status := bc.verifyChallengePage(rr, req, "1.2.3.4")

	if status != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, status)
	}
	if _, found := bc.verifiedCache.Get("1.2.3.4"); !found {
		t.Fatal("expected non-turnstile success response to set verified cache")
	}
}

func TestVerifyChallengePageMatchesTurnstileHostnameWithoutRequestPort(t *testing.T) {
	validChallengeTS := time.Now().Format(time.RFC3339Nano)
	mockResponse := fmt.Sprintf(`{"success":true,"hostname":"example.com","challenge_ts":%q}`, validChallengeTS)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockResponse))
	}))
	defer mockServer.Close()

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc.captchaConfig.validate = mockServer.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com:8443/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("cf-turnstile-response", "valid-token")

	rr := httptest.NewRecorder()
	status := bc.verifyChallengePage(rr, req, "1.2.3.4")

	if status != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, status)
	}
}

func TestVerifyChallengePageSendsTurnstileAdvancedValidationFields(t *testing.T) {
	validChallengeTS := time.Now().Format(time.RFC3339Nano)
	mockResponse := fmt.Sprintf(`{"success":true,"hostname":"example.com","challenge_ts":%q}`, validChallengeTS)
	var siteverifyForm url.Values

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		siteverifyForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockResponse))
	}))
	defer mockServer.Close()

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc.captchaConfig.validate = mockServer.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("cf-turnstile-response", "valid-token")

	status := bc.verifyChallengePage(httptest.NewRecorder(), req, "1.2.3.4")
	if status != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, status)
	}

	if got := siteverifyForm.Get("secret"); got != "test-secret" {
		t.Fatalf("expected secret %q, got %q", "test-secret", got)
	}
	if got := siteverifyForm.Get("response"); got != "valid-token" {
		t.Fatalf("expected response %q, got %q", "valid-token", got)
	}
	if got := siteverifyForm.Get("remoteip"); got != "1.2.3.4" {
		t.Fatalf("expected remoteip %q, got %q", "1.2.3.4", got)
	}

	idempotencyKey := siteverifyForm.Get("idempotency_key")
	if idempotencyKey == "" {
		t.Fatal("expected idempotency_key to be sent")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(idempotencyKey) {
		t.Fatalf("expected idempotency_key to be UUID v4, got %q", idempotencyKey)
	}
}

func TestVerifyChallengePageDoesNotSendTurnstileFieldsToOtherProviders(t *testing.T) {
	var siteverifyForm url.Values

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm failed: %v", err)
		}
		siteverifyForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer mockServer.Close()

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "hcaptcha"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc.captchaConfig.validate = mockServer.URL

	req := httptest.NewRequest(http.MethodPost, "http://example.com/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("h-captcha-response", "valid-token")

	status := bc.verifyChallengePage(httptest.NewRecorder(), req, "1.2.3.4")
	if status != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, status)
	}
	if got := siteverifyForm.Get("remoteip"); got != "" {
		t.Fatalf("expected remoteip to be omitted for hcaptcha, got %q", got)
	}
	if got := siteverifyForm.Get("idempotency_key"); got != "" {
		t.Fatalf("expected idempotency_key to be omitted for hcaptcha, got %q", got)
	}
}

func TestVerifyChallengePageHTTPError(t *testing.T) {
	// Test HTTP client error
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	// Set invalid URL to trigger HTTP error
	bc.captchaConfig.validate = "http://invalid-domain-that-does-not-exist-12345.com"

	req := httptest.NewRequest("POST", "http://example.com/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("cf-turnstile-response", "token")

	rr := httptest.NewRecorder()
	status := bc.verifyChallengePage(rr, req, "1.2.3.4")

	if status != http.StatusInternalServerError {
		t.Errorf("Expected status %d for HTTP error, got %d", http.StatusInternalServerError, status)
	}
}

func TestVerifyChallengePageInvalidJSON(t *testing.T) {
	// Test invalid JSON response
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{invalid json`))
	}))
	defer mockServer.Close()

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")
	bc.captchaConfig.validate = mockServer.URL

	req := httptest.NewRequest("POST", "http://example.com/challenge", nil)
	req.Form = make(map[string][]string)
	req.Form.Set("cf-turnstile-response", "token")

	rr := httptest.NewRecorder()
	status := bc.verifyChallengePage(rr, req, "1.2.3.4")

	if status != http.StatusInternalServerError {
		t.Errorf("Expected status %d for JSON error, got %d", http.StatusInternalServerError, status)
	}
}

func TestServeHTTPMethodNotAllowed(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.ChallengeURL = "/challenge"

	bc, _ := NewCaptchaProtect(context.Background(), next, config, "test")

	req := httptest.NewRequest("DELETE", "http://example.com/challenge", nil)
	req.RequestURI = "/challenge"
	rr := httptest.NewRecorder()

	bc.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestLoadStateInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.json")

	// Write invalid JSON
	if err := os.WriteFile(tmpFile, []byte(`{invalid json`), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}

	// Should not panic, just log error
	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Errorf("Should not fail on invalid state JSON: %v", err)
	}
	bc.loadStateFrom(tmpFile)

	if bc.verifiedCache.ItemCount() != 0 {
		t.Error("Verified cache should be empty after failed load")
	}

	// Clean up the file before temp dir cleanup
	_ = os.Remove(tmpFile)
	_ = os.Remove(tmpFile + ".lock")
}

func TestParseHttpMethodsInvalid(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.ProtectHttpMethods = []string{"GET", "INVALID_METHOD", "POST"}

	// Should not fail, just log warning
	_, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Errorf("Should not fail on invalid HTTP method: %v", err)
	}
}

func TestCircuitBreakerEnabled(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 30
	config.FailureThreshold = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bc, err := NewCaptchaProtect(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Verify circuit breaker is enabled
	if !bc.hasFallbackProvider {
		t.Error("Expected circuit breaker to be enabled")
	}

	// Verify initial state is closed
	if bc.circuitState != circuitClosed {
		t.Errorf("Expected initial circuit state to be closed, got %v", bc.circuitState)
	}

	// Verify primary config is active initially
	activeConfig := bc.getActiveCaptchaConfig()
	if activeConfig.js != bc.captchaConfig.js {
		t.Error("Expected primary config to be active initially")
	}
}

func TestCircuitBreakerDisabled(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 0
	config.FailureThreshold = 0

	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Verify circuit breaker is not enabled
	if bc.hasFallbackProvider {
		t.Error("Expected circuit breaker to be disabled")
	}

	// Should return primary config
	activeConfig := bc.getActiveCaptchaConfig()
	if activeConfig.js != bc.captchaConfig.js {
		t.Error("Expected primary config to be active when circuit breaker disabled")
	}
}

func TestHealthCheckOpensCircuit(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 30
	config.FailureThreshold = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bc, err := NewCaptchaProtect(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Simulate health check failures
	for i := 0; i < config.FailureThreshold; i++ {
		bc.recordHealthCheckFailure()
	}

	// Circuit should now be open
	bc.mu.RLock()
	state := bc.circuitState
	bc.mu.RUnlock()

	if state != circuitOpen {
		t.Errorf("Expected circuit to be open after %d health check failures, got state %v", config.FailureThreshold, state)
	}

	// Should now return PoJ provider config
	activeConfig := bc.getActiveCaptchaConfig()
	if activeConfig.js != "/captcha-protect-poj.js" {
		t.Errorf("Expected PoW JS path, got %s", activeConfig.js)
	}
	if activeConfig.key != "poj-captcha" {
		t.Errorf("Expected pow-captcha key, got %s", activeConfig.key)
	}
	if activeConfig.validate != "internal" {
		t.Errorf("Expected internal validation, got %s", activeConfig.validate)
	}
}

func TestHealthCheckClosesCircuit(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 30
	config.FailureThreshold = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bc, err := NewCaptchaProtect(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Open the circuit with health check failures
	for i := 0; i < config.FailureThreshold; i++ {
		bc.recordHealthCheckFailure()
	}

	// Verify circuit is open
	bc.mu.RLock()
	if bc.circuitState != circuitOpen {
		t.Error("Circuit should be open")
	}
	bc.mu.RUnlock()

	// Record a health check success
	bc.recordHealthCheckSuccess()

	// Circuit should now be closed
	bc.mu.RLock()
	state := bc.circuitState
	failureCount := bc.healthCheckFailureCount
	bc.mu.RUnlock()

	if state != circuitClosed {
		t.Errorf("Expected circuit to be closed after success, got %v", state)
	}

	if failureCount != 0 {
		t.Errorf("Expected failure count to be reset to 0, got %d", failureCount)
	}

	// Should return primary config again
	activeConfig := bc.getActiveCaptchaConfig()
	if activeConfig.js != bc.captchaConfig.js {
		t.Error("Expected primary config to be active after circuit closes")
	}
}

func TestCircuitBreakerConfiguration(t *testing.T) {
	tests := []struct {
		name             string
		periodSeconds    int
		failureThreshold int
		expectEnabled    bool
	}{
		{
			name:             "Enabled with both values",
			periodSeconds:    30,
			failureThreshold: 3,
			expectEnabled:    true,
		},
		{
			name:             "Disabled with zero period",
			periodSeconds:    0,
			failureThreshold: 3,
			expectEnabled:    false,
		},
		{
			name:             "Disabled with zero threshold",
			periodSeconds:    30,
			failureThreshold: 0,
			expectEnabled:    false,
		},
		{
			name:             "Disabled with both zero",
			periodSeconds:    0,
			failureThreshold: 0,
			expectEnabled:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			config := CreateConfig()
			config.SiteKey = "test"
			config.SecretKey = "test"
			config.ProtectRoutes = []string{"/"}
			config.CaptchaProvider = "turnstile"
			config.PeriodSeconds = tc.periodSeconds
			config.FailureThreshold = tc.failureThreshold

			bc, err := NewCaptchaProtect(ctx, nil, config, "test")
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if bc.hasFallbackProvider != tc.expectEnabled {
				t.Errorf("Expected circuit breaker enabled=%v, got %v", tc.expectEnabled, bc.hasFallbackProvider)
			}
		})
	}
}

func TestGetCaptchaConfig(t *testing.T) {
	tests := []struct {
		provider string
		wantJS   string
		wantKey  string
	}{
		{
			provider: "turnstile",
			wantJS:   "https://challenges.cloudflare.com/turnstile/v0/api.js",
			wantKey:  "cf-turnstile",
		},
		{
			provider: "recaptcha",
			wantJS:   "https://www.google.com/recaptcha/api.js",
			wantKey:  "g-recaptcha",
		},
		{
			provider: "hcaptcha",
			wantJS:   "https://hcaptcha.com/1/api.js",
			wantKey:  "h-captcha",
		},
		{
			provider: "poj",
			wantJS:   "/captcha-protect-poj.js",
			wantKey:  "poj-captcha",
		},
		{
			provider: "invalid",
			wantJS:   "",
			wantKey:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			config := getCaptchaConfig(tc.provider)
			if config.js != tc.wantJS {
				t.Errorf("Expected JS %q, got %q", tc.wantJS, config.js)
			}
			if config.key != tc.wantKey {
				t.Errorf("Expected key %q, got %q", tc.wantKey, config.key)
			}
		})
	}
}

func TestServePojJS(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-key"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}

	bc, err := NewCaptchaProtect(t.Context(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/captcha-protect-poj.js", nil)
	rw := httptest.NewRecorder()

	bc.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rw.Code)
	}

	contentType := rw.Header().Get("Content-Type")
	if contentType != "application/javascript" {
		t.Errorf("Expected Content-Type application/javascript, got %s", contentType)
	}

	body := rw.Body.String()
	if !strings.Contains(body, "data-callback") {
		t.Error("Expected PoJ JS to reference data-callback")
	}
}

func TestVerifyPowChallenge(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-key"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "poj"

	bc, err := NewCaptchaProtect(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	tests := []struct {
		name           string
		challenge      string
		expectedStatus int
	}{
		{
			name:           "Valid PoJ",
			challenge:      "test-challenge",
			expectedStatus: http.StatusFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create POST request with PoW token
			form := url.Values{}
			form.Add("poj-captcha-response", "foo")
			form.Add("destination", "/")

			req := httptest.NewRequest(http.MethodPost, "/challenge", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "192.0.2.1:1234"

			rw := httptest.NewRecorder()

			bc.ServeHTTP(rw, req)

			if rw.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rw.Code)
			}
		})
	}
}

func TestCircuitBreakerUsesPojProvider(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-key"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 30
	config.FailureThreshold = 3

	bc, err := NewCaptchaProtect(t.Context(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Initially should use primary provider
	activeConfig := bc.getActiveCaptchaConfig()
	if activeConfig.js != "https://challenges.cloudflare.com/turnstile/v0/api.js" {
		t.Errorf("Expected primary provider (turnstile), got %s", activeConfig.js)
	}

	// Simulate health check failures to open circuit
	for i := 0; i < config.FailureThreshold; i++ {
		bc.recordHealthCheckFailure()
	}

	// Now should use PoJ provider
	activeConfig = bc.getActiveCaptchaConfig()
	if activeConfig.js != "/captcha-protect-poj.js" {
		t.Errorf("Expected PoJ provider when circuit is open, got %s", activeConfig.js)
	}
	if activeConfig.key != "poj-captcha" {
		t.Errorf("Expected poj-captcha key when circuit is open, got %s", activeConfig.key)
	}
	if activeConfig.validate != "internal" {
		t.Errorf("Expected internal validation when circuit is open, got %s", activeConfig.validate)
	}

	// Health check success should close circuit
	bc.recordHealthCheckSuccess()

	// Should return to primary provider
	activeConfig = bc.getActiveCaptchaConfig()
	if activeConfig.js != "https://challenges.cloudflare.com/turnstile/v0/api.js" {
		t.Errorf("Expected primary provider after circuit closes, got %s", activeConfig.js)
	}
}

func TestPojChallengeGeneration(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-key"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "poj"
	config.PeriodSeconds = 0 // Disable circuit breaker
	config.FailureThreshold = 0

	bc, err := NewCaptchaProtect(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}), config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Request the challenge page directly with PoW provider
	req := httptest.NewRequest(http.MethodGet, "/challenge?destination=%2F", nil)
	req.RemoteAddr = "203.0.113.1:1234"

	rw := httptest.NewRecorder()
	bc.ServeHTTP(rw, req)

	body := rw.Body.String()

	// Check that challenge and difficulty are included in the response
	if !strings.Contains(body, "data-callback=") {
		t.Errorf("Expected data-callback attribute in PoW challenge page")
	}
	if !strings.Contains(body, "/captcha-protect-poj.js") {
		t.Errorf("Expected PoJ JS URL in challenge page")
	}
}

func TestPerformHealthCheckSuccessResetsFailures(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 3600
	config.FailureThreshold = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bc, err := NewCaptchaProtect(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bc.captchaConfig.js = server.URL
	bc.recordHealthCheckFailure()

	bc.performHealthCheck()

	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if bc.healthCheckFailureCount != 0 {
		t.Fatalf("expected failure count reset to 0, got %d", bc.healthCheckFailureCount)
	}
	if bc.circuitState != circuitClosed {
		t.Fatalf("expected circuit to be closed, got %v", bc.circuitState)
	}
}

func TestPerformHealthCheckFailurePaths(t *testing.T) {
	tests := []struct {
		name      string
		jsURL     string
		status    int
		expectErr bool
	}{
		{
			name:   "404 considered failure",
			status: http.StatusNotFound,
		},
		{
			name:   "503 considered failure",
			status: http.StatusServiceUnavailable,
		},
		{
			name:      "invalid URL request creation failure",
			jsURL:     "://invalid-url",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := CreateConfig()
			config.SiteKey = "test"
			config.SecretKey = "test"
			config.ProtectRoutes = []string{"/"}
			config.CaptchaProvider = "turnstile"
			config.PeriodSeconds = 3600
			config.FailureThreshold = 1

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			bc, err := NewCaptchaProtect(ctx, nil, config, "test")
			if err != nil {
				t.Fatalf("Failed to create CaptchaProtect: %v", err)
			}

			if tt.expectErr {
				bc.captchaConfig.js = tt.jsURL
			} else {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.status)
				}))
				defer server.Close()
				bc.captchaConfig.js = server.URL
			}

			bc.performHealthCheck()

			bc.mu.RLock()
			defer bc.mu.RUnlock()
			if bc.healthCheckFailureCount != 1 {
				t.Fatalf("expected failure count 1, got %d", bc.healthCheckFailureCount)
			}
			if bc.circuitState != circuitOpen {
				t.Fatalf("expected circuit to open, got %v", bc.circuitState)
			}
		})
	}
}

func TestVerifyChallengePagePojFallbackUsesOneHourTTL(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-key"
	config.SecretKey = "test-secret"
	config.ProtectRoutes = []string{"/"}
	config.CaptchaProvider = "turnstile"
	config.PeriodSeconds = 3600
	config.FailureThreshold = 1

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bc, err := NewCaptchaProtect(ctx, nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	// Open the circuit so PoJ becomes active fallback provider.
	bc.recordHealthCheckFailure()

	form := url.Values{}
	form.Add("poj-captcha-response", "ok")
	form.Add("destination", "%2F")
	req := httptest.NewRequest(http.MethodPost, "/challenge", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	clientIP := "203.0.113.10"

	status := bc.verifyChallengePage(rr, req, clientIP)
	if status != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, status)
	}

	item, found := bc.verifiedCache.Items()[clientIP]
	if !found {
		t.Fatalf("expected %s to be in verified cache", clientIP)
	}

	remaining := time.Until(time.Unix(0, item.Expiration))
	if remaining < 50*time.Minute || remaining > 70*time.Minute {
		t.Fatalf("expected PoJ fallback TTL around 1h, got %s", remaining)
	}
}

func TestGooglebotIPCheckLoopInitialFetchSuccess(t *testing.T) {
	originalURLs := helper.GoogleCrawlerIPRangeURLs
	defer func() { helper.GoogleCrawlerIPRangeURLs = originalURLs }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`))
	}))
	defer server.Close()

	helper.GoogleCrawlerIPRangeURLs = []string{server.URL}

	bc := &CaptchaProtect{
		log:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
		httpClient:   server.Client(),
		googlebotIPs: helper.NewGooglebotIPs(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bc.googlebotIPCheckLoop(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bc.googlebotIPs.Contains(net.ParseIP("203.0.113.10")) {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	<-done
	t.Fatal("expected googlebot IPs to be updated from initial crawler fetch")
}

func TestGooglebotIPCheckLoopInitialFetchError(t *testing.T) {
	originalURLs := helper.GoogleCrawlerIPRangeURLs
	defer func() { helper.GoogleCrawlerIPRangeURLs = originalURLs }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	helper.GoogleCrawlerIPRangeURLs = []string{server.URL}

	bc := &CaptchaProtect{
		log:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
		httpClient:   server.Client(),
		googlebotIPs: helper.NewGooglebotIPs(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		bc.googlebotIPCheckLoop(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if bc.googlebotIPs.Contains(net.ParseIP("203.0.113.10")) {
		t.Fatal("did not expect googlebot IPs to update when initial fetch fails")
	}
}

func TestUptimeRobotIPCheckLoopInitialFetch(t *testing.T) {
	originalURL := helper.UptimeRobotIPRangeURL
	defer func() { helper.UptimeRobotIPRangeURL = originalURL }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ip_prefix":"203.0.113.10/32"}]}`))
	}))
	defer server.Close()
	helper.UptimeRobotIPRangeURL = server.URL

	bc := &CaptchaProtect{
		log:            slog.New(slog.NewTextHandler(os.Stdout, nil)),
		httpClient:     server.Client(),
		uptimeRobotIPs: helper.NewUptimeRobotIPs(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		uptimeRobotIPCheckLoop(ctx, bc.log, bc.httpClient, bc.uptimeRobotIPs)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bc.uptimeRobotIPs.Contains(net.ParseIP("203.0.113.10")) {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	<-done
	t.Fatal("expected UptimeRobot IPs to be updated from initial fetch")
}

func TestServeChallengePageEscapesDestination(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test-site-key"
	config.SecretKey = "test-secret-key"
	config.ProtectRoutes = []string{"/"}
	config.ChallengeStatusCode = http.StatusTooManyRequests

	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Fatalf("Failed to create CaptchaProtect: %v", err)
	}

	rr := httptest.NewRecorder()
	maliciousDestination := `" /><script>alert(1)</script>`

	bc.serveChallengePage(rr, maliciousDestination)

	body := rr.Body.String()
	if !strings.Contains(body, `value="&#34; /&gt;&lt;script&gt;alert(1)&lt;/script&gt;"`) {
		t.Fatalf("expected destination to be HTML-escaped in attribute context, body=%q", body)
	}
	if strings.Contains(body, `value="" /><script>alert(1)</script>`) {
		t.Fatalf("expected raw destination not to be injected into HTML, body=%q", body)
	}
}

func TestNormalizeDestination(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		want        string
	}{
		{name: "empty", destination: "", want: "/"},
		{name: "decoded local path", destination: "/home?foo=bar", want: "/home?foo=bar"},
		{name: "encoded local path", destination: "%2Fhome%3Ffoo%3Dbar", want: "/home?foo=bar"},
		{name: "decoded path with literal plus", destination: "/Chrome%20+%20MariaDB%20", want: "/Chrome%20+%20MariaDB%20"},
		{name: "encoded path with literal plus", destination: "%2FChrome%2520%2B%2520MariaDB%2520", want: "/Chrome%20+%20MariaDB%20"},
		{name: "absolute url", destination: "https://evil.com/phish", want: "/"},
		{name: "protocol relative url", destination: "//evil.com/phish", want: "/"},
		{name: "relative path", destination: "home", want: "/"},
		{name: "invalid escape", destination: "%ZZ", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDestination(tt.destination); got != tt.want {
				t.Fatalf("normalizeDestination(%q) = %q, want %q", tt.destination, got, tt.want)
			}
		})
	}
}
