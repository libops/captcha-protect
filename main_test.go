package captcha_protect

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

func init() {
	log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

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
