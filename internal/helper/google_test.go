package helper

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestGooglebotIPs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	g := NewGooglebotIPs()

	if g == nil {
		t.Fatal("NewGooglebotIPs returned nil")
	}

	cidrs := []string{
		"8.8.8.8/32",
		"2001:4860:4860::8888/128",
	}

	g.Update(cidrs, log)

	if !g.Contains(net.ParseIP("8.8.8.8")) {
		t.Error("Expected 8.8.8.8 to be a Googlebot IP")
	}

	if g.Contains(net.ParseIP("1.1.1.1")) {
		t.Error("Expected 1.1.1.1 not to be a Googlebot IP")
	}

	if !g.Contains(net.ParseIP("2001:4860:4860::8888")) {
		t.Error("Expected 2001:4860:4860::8888 to be a Googlebot IP")
	}

	if g.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("Expected 2001:db8::1 not to be a Googlebot IP")
	}
}
func TestFetchGooglebotIPs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{
			"prefixes": [
				{
					"ipv4Prefix": "8.8.8.0/24"
				},
				{
					"ipv6Prefix": "2001:4860::/32"
				}
			]
		}`))
		if err != nil {
			t.Fatalf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	cidrs, err := FetchGooglebotIPs(log, server.Client(), server.URL)
	if err != nil {
		t.Fatalf("FetchGooglebotIPs failed: %v", err)
	}

	expectedCIDRs := []string{"8.8.8.0/24", "2001:4860::/32"}
	if len(cidrs) != len(expectedCIDRs) {
		t.Errorf("Expected %d CIDRs, got %d", len(expectedCIDRs), len(cidrs))
	}

	for i, cidr := range cidrs {
		if cidr != expectedCIDRs[i] {
			t.Errorf("Expected CIDR %s, got %s", expectedCIDRs[i], cidr)
		}
	}
}
