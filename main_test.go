package captcha_protect

import (
	"errors"
	"net"
	"strings"
	"testing"
)

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
			wantSubnet: "192",
		},
		{
			name:       "IPv4 /16",
			ip:         "192.168.1.1",
			ipv4Mask:   16,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168",
		},
		{
			name:       "IPv4 /24",
			ip:         "192.168.1.1",
			ipv4Mask:   24,
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168.1",
		},
		{
			name:       "IPv4 unrecognized mask falls back to /16",
			ip:         "192.168.1.1",
			ipv4Mask:   32, // not one of the allowed values; fallback in our implementation is /16.
			wantFull:   "192.168.1.1",
			wantSubnet: "192.168",
		},
		{
			name:     "IPv6 /64",
			ip:       "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			ipv6Mask: 64,
			wantFull: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			// for /64, we keep 4 hextets
			wantSubnet: strings.Join(strings.Split("2001:0db8:85a3:0000:0000:8a2e:0370:7334", ":")[:4], ":"),
		},
		{
			name:     "IPv6 /48",
			ip:       "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			ipv6Mask: 48,
			wantFull: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			// for /48, we keep 3 hextets
			wantSubnet: strings.Join(strings.Split("2001:0db8:85a3:0000:0000:8a2e:0370:7334", ":")[:3], ":"),
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
			gotFull, gotSubnet := ParseIp(tc.ip, tc.ipv4Mask, tc.ipv6Mask)
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
	// Helper function to parse CIDR blocks
	parseCIDR := func(cidr string) *net.IPNet {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("Failed to parse CIDR %s: %v", cidr, err)
		}
		return block
	}

	tests := []struct {
		name      string
		clientIP  string
		exemptIps []*net.IPNet
		expected  bool
	}{
		{
			name:      "IP in exempt subnet",
			clientIP:  "192.168.1.5",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24")},
			expected:  true,
		},
		{
			name:      "IP not in exempt subnet",
			clientIP:  "192.168.2.5",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24")},
			expected:  false,
		},
		{
			name:      "Multiple exempt subnets, matching one",
			clientIP:  "10.0.0.15",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24"), parseCIDR("10.0.0.0/16")},
			expected:  true,
		},
		{
			name:      "IPv6 address in exempt range",
			clientIP:  "2001:db8::1",
			exemptIps: []*net.IPNet{parseCIDR("2001:db8::/32")},
			expected:  true,
		},
		{
			name:      "IPv6 address not in exempt range",
			clientIP:  "2001:db9::1",
			exemptIps: []*net.IPNet{parseCIDR("2001:db8::/32")},
			expected:  false,
		},
		{
			name:      "Invalid IP address",
			clientIP:  "invalid-ip",
			exemptIps: []*net.IPNet{parseCIDR("192.168.1.0/24")},
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
				ProtectRoutes:         []string{"/"},
				ProtectFileExtensions: []string{},
			},
			path:     "/foo",
			expected: true,
		},
		{
			name: "Unprotected route",
			config: Config{
				ProtectRoutes:         []string{"/foo"},
				ProtectFileExtensions: []string{},
			},
			path:     "/bar",
			expected: false,
		},
		{
			name: "Protected route with included file extension",
			config: Config{
				ProtectRoutes:         []string{"/foo"},
				ProtectFileExtensions: []string{"css", "js"},
			},
			path:     "/foo/bar/style.css",
			expected: true,
		},
		{
			name: "json always protected",
			config: Config{
				ProtectRoutes:         []string{"/"},
				ProtectFileExtensions: []string{"css", "js"},
			},
			path:     "/foo/data.json",
			expected: true,
		},
		{
			name: "html always protected",
			config: Config{
				ProtectRoutes:         []string{"/"},
				ProtectFileExtensions: []string{"css", "js"},
			},
			path:     "/foo/bar/data.html",
			expected: true,
		},
		{
			name: "subpath route protection",
			config: Config{
				ProtectRoutes:         []string{"/foo"},
				ProtectFileExtensions: []string{},
			},
			path:     "/foo/any/route",
			expected: true,
		},
		{
			name: "No routes protected",
			config: Config{
				ProtectRoutes:         []string{},
				ProtectFileExtensions: []string{},
			},
			path:     "/any/route",
			expected: false,
		},
		{
			name: "File extension in unprotected route",
			config: Config{
				ProtectRoutes:         []string{"/protected"},
				ProtectFileExtensions: []string{"css", "js"},
			},
			path:     "/unprotected/script.js",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CreateConfig()
			c.ProtectRoutes = append(c.ProtectRoutes, tt.config.ProtectRoutes...)
			c.ProtectFileExtensions = append(c.ProtectFileExtensions, tt.config.ProtectFileExtensions...)
			bc := &CaptchaProtect{
				config: c,
			}

			result := bc.RouteIsProtected(tt.path)
			if result != tt.expected {
				t.Errorf("RouteIsProtected(%q) = %v; want %v", tt.path, result, tt.expected)
			}
		})
	}
}
