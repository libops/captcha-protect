package helper

import (
	"errors"
	"net"
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

func parseCIDR(cidr string, t *testing.T) *net.IPNet {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("Failed to parse CIDR %s: %v", cidr, err)
	}
	return block
}

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr bool
	}{
		{
			name:      "Valid IPv4 CIDR",
			cidr:      "192.168.1.0/24",
			expectErr: false,
		},
		{
			name:      "Valid IPv6 CIDR",
			cidr:      "2001:db8::/32",
			expectErr: false,
		},
		{
			name:      "Invalid CIDR - no mask",
			cidr:      "192.168.1.0",
			expectErr: true,
		},
		{
			name:      "Invalid CIDR - bad format",
			cidr:      "not-a-cidr",
			expectErr: true,
		},
		{
			name:      "Invalid CIDR - empty string",
			cidr:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseCIDR(tt.cidr)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for CIDR %q, got nil", tt.cidr)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for CIDR %q: %v", tt.cidr, err)
				}
				if result == nil {
					t.Errorf("Expected non-nil result for valid CIDR %q", tt.cidr)
				}
			}
		})
	}
}
