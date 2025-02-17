package captcha_protect

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
