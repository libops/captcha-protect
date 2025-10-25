package captcha_protect

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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
	config.GoodBots = []string{"googlebot.com"}

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
		{"/no-extension", true}, // No extension = protected
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
	jsonData, _ := json.Marshal(map[string]interface{}{
		"rate": map[string]uint{
			"192.168.0.0": 10,
		},
		"verified": map[string]bool{
			"1.2.3.4": true,
		},
		"bots": map[string]bool{
			"5.6.7.8": false,
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
