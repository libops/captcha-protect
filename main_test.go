package captcha_protect

import (
	"context"
	"encoding/json"
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

func TestParseIp(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		ipv4Mask   int
		ipv6Mask   int
		wantFull   string
		wantSubnet string
	}{
		{
			name:       "IPv4 /8",
			ip:         "192.168.1.1",
			ipv4Mask:   8,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.0.0.0",
		},
		{
			name:       "IPv4 /10",
			ip:         "192.168.1.1",
			ipv4Mask:   10,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.128.0.0",
		},
		{
			name:       "IPv4 /16",
			ip:         "192.168.1.1",
			ipv4Mask:   16,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168.0.0",
		},
		{
			name:       "IPv4 /20",
			ip:         "192.168.1.1",
			ipv4Mask:   20,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168.0.0",
		},
		{
			name:       "IPv4 /24",
			ip:         "192.168.1.1",
			ipv4Mask:   24,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168.1.0",
		},
		{
			name:       "IPv4 /32",
			ip:         "192.168.1.1",
			ipv4Mask:   32,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168.1.1",
		},
		{
			name:       "IPv6 /64",
			ip:         "2001:0db8:85a3:1234:5678:8a2e:0370:7334",
			ipv6Mask:   64,
			wantFull:   "2001:0db8:85a3:1234:5678:8a2e:0370:7334",
			wantSubnet: "2001:db8:85a3:1234::",
		},
		{
			name:       "IPv6 /48",
			ip:         "2001:0db8:85a3:1234:5678:8a2e:0370:7334",
			ipv6Mask:   48,
			wantFull:   "2001:0db8:85a3:1234:5678:8a2e:0370:7334",
			wantSubnet: "2001:db8:85a3::",
		},
		{
			name:       "Invalid IP returns same string",
			ip:         "not.an.ip",
			ipv4Mask:   16,
			ipv6Mask:   64,
			wantFull:   "not.an.ip",
			wantSubnet: "not.an.ip",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := CreateConfig()
			bc := &CaptchaProtect{
				config:   c,
				ipv4Mask: net.CIDRMask(tc.ipv4Mask, 32),
				ipv6Mask: net.CIDRMask(tc.ipv6Mask, 128),
			}
			gotFull, gotSubnet := bc.ParseIp(tc.ip)
			if gotFull != tc.wantFull {
				t.Errorf("ParseIp(%q, %d, %d) got full = %q, want %q", tc.ip, tc.ipv4Mask, tc.ipv6Mask, gotFull, tc.wantFull)
			}
			if gotSubnet != tc.wantSubnet {
				t.Errorf("ParseIp(%q, %d, %d) got subnet = %q, want %q", tc.ip, tc.ipv4Mask, tc.ipv6Mask, gotSubnet, tc.wantSubnet)
			}
		})
	}
}

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

			ip, _ := bc.getClientIP(req)
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
		rateLimit      uint
		expectedStatus uint
		challengePage  string
		expectedBody   string
		challengeCode  int
	}{
		{
			name:           "Redirect to 302",
			rateLimit:      0,
			challengePage:  "/challenge",
			expectedStatus: http.StatusFound,
			expectedBody:   "/challenge?destination=%2Fsomepath",
			challengeCode:  http.StatusOK,
		},
		{
			name:           "403 when changing default challenge code",
			rateLimit:      0,
			challengePage:  "/challenge",
			expectedStatus: http.StatusFound,
			challengeCode:  http.StatusForbidden,
			expectedBody:   "/challenge?destination=%2Fsomepath",
		},
		{
			name:           "429 when challenging on same page",
			rateLimit:      0,
			challengePage:  "",
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   "One moment while we verify your network connection",
			challengeCode:  http.StatusTooManyRequests,
		},
		{
			name:           "403 when challenging on same page",
			rateLimit:      0,
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
			config.RateLimit = tc.rateLimit
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

func TestIsGoodUserAgent(t *testing.T) {
	tests := []struct {
		name             string
		exemptUserAgents []string
		ua               string
		expected         bool
	}{
		{"Matching first prefix", []string{"Mozilla", "Google"}, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", true},
		{"Matching second prefix", []string{"Bing", "Edge"}, "Edge/12.0", true},
		{"Case insensitive", []string{"bing", "Edge"}, "BING/12.0", true},
		{"No matching prefix", []string{"Mozilla", "Google"}, "Safari/537.36", false},
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
			name:         "Invalid IPv4 mask - too small",
			modifyConfig: func(c *Config) { c.IPv4SubnetMask = 5 },
			expectError:  "invalid ipv4 mask",
		},
		{
			name:         "Invalid IPv4 mask - too large",
			modifyConfig: func(c *Config) { c.IPv4SubnetMask = 33 },
			expectError:  "invalid ipv4 mask",
		},
		{
			name:         "Invalid IPv6 mask - too small",
			modifyConfig: func(c *Config) { c.IPv6SubnetMask = 5 },
			expectError:  "invalid ipv6 mask",
		},
		{
			name:         "Invalid IPv6 mask - too large",
			modifyConfig: func(c *Config) { c.IPv6SubnetMask = 200 },
			expectError:  "invalid ipv6 mask",
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

func TestRateLimiting(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.RateLimit = 5
	config.Window = 10

	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Fatal(err)
	}

	subnet := "192.168.0.0"

	// Register 5 requests (at rate limit)
	for i := 0; i < 5; i++ {
		bc.registerRequest(subnet)
		if bc.trippedRateLimit(subnet) {
			t.Errorf("Should not trip rate limit at %d requests", i+1)
		}
	}

	// 6th request should trip
	bc.registerRequest(subnet)
	if !bc.trippedRateLimit(subnet) {
		t.Error("Should trip rate limit after exceeding")
	}

	// Different subnet should not be affected
	differentSubnet := "10.0.0.0"
	bc.registerRequest(differentSubnet)
	if bc.trippedRateLimit(differentSubnet) {
		t.Error("Different subnet should not be rate limited")
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
	config.RateLimit = 0 // Always challenge unless verified

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

func TestStatsPage(t *testing.T) {
	config := CreateConfig()
	config.SiteKey = "test"
	config.SecretKey = "test"
	config.ProtectRoutes = []string{"/"}
	config.EnableStatsPage = "true"

	bc, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	// Add some test data
	bc.rateCache.Set("192.168.0.0", uint(10), 1*time.Hour)
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
				// Check that we have expected keys
				if _, ok := stats["rate"]; !ok {
					t.Error("Stats JSON missing 'rate' key")
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
	config.RateLimit = 0 // Always challenge

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
	config.PersistentStateFile = tmpFile

	// Don't pass a context to avoid starting background goroutines
	bc1, _ := NewCaptchaProtect(context.Background(), nil, config, "test")

	// Add some state
	bc1.rateCache.Set("192.168.0.0", uint(10), 1*time.Hour)
	bc1.verifiedCache.Set("1.2.3.4", true, 1*time.Hour)
	bc1.botCache.Set("5.6.7.8", false, 1*time.Hour)

	// Manually save state by writing the file directly
	// This tests the state format without relying on the background goroutine
	// Use the new CacheEntry format with expiration timestamps
	futureExpiration := time.Now().Add(1 * time.Hour).UnixNano()
	jsonData, _ := json.Marshal(map[string]interface{}{
		"rate": map[string]map[string]interface{}{
			"192.168.0.0": {
				"value":      uint(10),
				"expiration": float64(futureExpiration),
			},
		},
		"verified": map[string]map[string]interface{}{
			"1.2.3.4": {
				"value":      true,
				"expiration": float64(futureExpiration),
			},
		},
		"bots": map[string]map[string]interface{}{
			"5.6.7.8": {
				"value":      false,
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

	// Check rate cache
	val, found := bc2.rateCache.Get("192.168.0.0")
	if !found || val.(uint) != 10 {
		t.Error("Rate cache state not persisted correctly")
	}

	// Check verified cache
	_, found = bc2.verifiedCache.Get("1.2.3.4")
	if !found {
		t.Error("Verified cache state not persisted correctly")
	}

	// Check bot cache
	botVal, found := bc2.botCache.Get("5.6.7.8")
	if !found || botVal.(bool) != false {
		t.Error("Bot cache state not persisted correctly")
	}
}

func TestVerifyChallengePage(t *testing.T) {
	tests := []struct {
		name           string
		provider       string
		formValues     map[string]string
		mockResponse   string
		expectedStatus int
		shouldSetCache bool
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
			mockResponse:   `{"success":true}`,
			expectedStatus: http.StatusFound,
			shouldSetCache: true,
		},
		{
			name:     "Successful verification without destination",
			provider: "recaptcha",
			formValues: map[string]string{
				"g-recaptcha-response": "valid-token",
			},
			mockResponse:   `{"success":true}`,
			expectedStatus: http.StatusFound,
			shouldSetCache: true,
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
			mockResponse:   `{"success":true}`,
			expectedStatus: http.StatusFound,
			shouldSetCache: true,
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
		})
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
	config.PersistentStateFile = tmpFile

	// Should not panic, just log error
	bc, err := NewCaptchaProtect(context.Background(), nil, config, "test")
	if err != nil {
		t.Errorf("Should not fail on invalid state JSON: %v", err)
	}

	// Caches should be empty
	if bc.rateCache.ItemCount() != 0 {
		t.Error("Rate cache should be empty after failed load")
	}

	// Clean up the file before temp dir cleanup
	_ = os.Remove(tmpFile)
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

	bc, err := NewCaptchaProtect(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test")
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

	bc, err := NewCaptchaProtect(context.Background(), http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}), config, "test")
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
