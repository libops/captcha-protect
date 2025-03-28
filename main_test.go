package captcha_protect

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func init() {
	log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestIsIpGoodBot(t *testing.T) {
	// Save the original functions and restore them at the end.
	origLookupAddr := lookupAddrFunc
	origLookupIP := lookupIPFunc
	defer func() {
		lookupAddrFunc = origLookupAddr
		lookupIPFunc = origLookupIP
	}()

	tests := []struct {
		name             string
		clientIP         string
		goodBots         []string
		lookupAddrReturn []string
		lookupAddrErr    error
		lookupIPReturn   []net.IP
		lookupIPErr      error
		expected         bool
	}{
		{
			name:             "DNS lookup fails",
			clientIP:         "1.2.3.4",
			goodBots:         []string{"google.com"},
			lookupAddrReturn: nil,
			lookupAddrErr:    errors.New("dns error"),
			expected:         false,
		},
		{
			name:             "Empty hostname result",
			clientIP:         "1.2.3.4",
			goodBots:         []string{"google.com"},
			lookupAddrReturn: []string{},
			lookupAddrErr:    nil,
			expected:         false,
		},
		{
			name:     "Spoofed hostname: resolved IP does not match clientIP",
			clientIP: "1.2.3.4",
			goodBots: []string{"google.com"},
			lookupAddrReturn: []string{
				"host.example.com.",
			},
			lookupAddrErr: nil,
			lookupIPReturn: []net.IP{
				net.ParseIP("5.6.7.8"),
			},
			lookupIPErr: nil,
			expected:    false,
		},
		{
			name:     "Hostname does not have enough parts",
			clientIP: "1.2.3.4",
			goodBots: []string{"example.com"},
			lookupAddrReturn: []string{
				"localhost.",
			},
			lookupAddrErr: nil,
			lookupIPReturn: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			lookupIPErr: nil,
			expected:    false,
		},
		{
			name:     "Not a good bot because domain does not match",
			clientIP: "1.2.3.4",
			goodBots: []string{"google.com"},
			lookupAddrReturn: []string{
				"foo.bar.example.com.",
			},
			lookupAddrErr: nil,
			lookupIPReturn: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			lookupIPErr: nil,
			expected:    false,
		},
		{
			name:     "Is a good bot",
			clientIP: "1.2.3.4",
			goodBots: []string{"example.com"},
			lookupAddrReturn: []string{
				"194.114.135.34.bc.example.com.",
			},
			lookupAddrErr: nil,
			lookupIPReturn: []net.IP{
				net.ParseIP("1.2.3.4"),
			},
			lookupIPErr: nil,
			expected:    true,
		},
	}

	for _, tc := range tests {
		lookupAddrFunc = func(ip string) ([]string, error) {
			if ip != tc.clientIP {
				t.Errorf("Expected lookupAddr to be called with %q; got %q", tc.clientIP, ip)
			}
			return tc.lookupAddrReturn, tc.lookupAddrErr
		}

		lookupIPFunc = func(host string) ([]net.IP, error) {
			if len(tc.lookupAddrReturn) == 0 || host != tc.lookupAddrReturn[0] {
				t.Errorf("Expected lookupIP to be called with %q; got %q", tc.lookupAddrReturn[0], host)
			}
			return tc.lookupIPReturn, tc.lookupIPErr
		}

		t.Run(tc.name, func(t *testing.T) {
			result := IsIpGoodBot(tc.clientIP, tc.goodBots)
			if result != tc.expected {
				t.Errorf("IsIpGoodBot(%q) = %v; expected %v", tc.clientIP, result, tc.expected)
			}
		})
	}
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

func TestIsIpExcluded(t *testing.T) {
	tests := []struct {
		name      string
		clientIP  string
		exemptIps []*net.IPNet
		expected  bool
	}{
		{
			name:      "IP in exempt subnet",
			clientIP:  "192.168.1.5",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24", t)},
			expected:  true,
		},
		{
			name:      "IP not in exempt subnet",
			clientIP:  "192.168.2.5",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24", t)},
			expected:  false,
		},
		{
			name:      "Multiple exempt subnets, matching one",
			clientIP:  "10.0.0.15",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24", t), parseCIDR("10.0.0.0/16", t)},
			expected:  true,
		},
		{
			name:      "IPv6 address in exempt range",
			clientIP:  "2001:db8::1",
			exemptIps: []*net.IPNet{parseCIDR("2001:db8::/32", t)},
			expected:  true,
		},
		{
			name:      "IPv6 address not in exempt range",
			clientIP:  "2001:db9::1",
			exemptIps: []*net.IPNet{parseCIDR("2001:db8::/32", t)},
			expected:  false,
		},
		{
			name:      "Invalid IP address",
			clientIP:  "invalid-ip",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24", t)},
			expected:  false,
		},
		{
			name:      "No exempt IPs",
			clientIP:  "192.168.1.5",
			exemptIps: []*net.IPNet{},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsIpExcluded(tt.clientIP, tt.exemptIps)
			if result != tt.expected {
				t.Errorf("IsIpExcluded(%q) = %v; want %v", tt.clientIP, result, tt.expected)
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
		t.Run(tt.name, func(t *testing.T) {
			c := CreateConfig()
			c.ProtectRoutes = append(c.ProtectRoutes, tt.config.ProtectRoutes...)
			c.ExcludeRoutes = append(c.ExcludeRoutes, tt.config.ExcludeRoutes...)
			c.ProtectFileExtensions = append(c.ProtectFileExtensions, tt.config.ProtectFileExtensions...)
			bc, err := NewCaptchaProtect(context.Background(), nil, c, "captcha-protect")
			if err != nil {
				t.Errorf("unexpected error %v", err)
			}

			result := bc.RouteIsProtected(tt.path)
			if result != tt.expected {
				t.Errorf("RouteIsProtected(%q) = %v; want %v", tt.path, result, tt.expected)
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

func parseCIDR(cidr string, t *testing.T) *net.IPNet {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("Failed to parse CIDR %s: %v", cidr, err)
	}
	return block
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
	}{
		{
			name:           "Redirect to 302",
			rateLimit:      0,
			challengePage:  "/challenge",
			expectedStatus: http.StatusFound,
			expectedBody:   "/challenge?destination=%2Fsomepath",
		},
		{
			name:           "429 on same page",
			rateLimit:      0,
			challengePage:  "",
			expectedStatus: http.StatusTooManyRequests,
			expectedBody:   "One moment while we verify your network connection",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config.RateLimit = tc.rateLimit
			config.CaptchaProvider = "turnstile"
			config.ProtectRoutes = []string{"/"}
			config.ChallengeURL = tc.challengePage
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
		})
	}
}
