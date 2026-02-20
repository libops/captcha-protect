package helper

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
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

func TestReduceCIDRs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	input := []string{
		"8.8.8.0/24",
		"8.8.8.0/25",
		"8.8.8.128/25",
		"8.8.8.0/24", // duplicate
		"2001:4860::/32",
		"2001:4860:1234::/48",
	}

	got := ReduceCIDRs(input, log)
	want := []string{"8.8.8.0/24", "2001:4860::/32"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reduced CIDRs: got %v want %v", got, want)
	}
}

func TestFetchGoogleCrawlerIPs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"}]}`))
	}))
	defer serverA.Close()

	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/25"},{"ipv6Prefix":"2001:4860::/32"}]}`))
	}))
	defer serverB.Close()

	got, err := FetchGoogleCrawlerIPs(log, serverA.Client(), []string{serverA.URL, serverB.URL})
	if err != nil {
		t.Fatalf("FetchGoogleCrawlerIPs failed: %v", err)
	}

	want := []string{"8.8.8.0/24", "2001:4860::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected CIDRs: got %v want %v", got, want)
	}
}

func TestFetchGoogleCrawlerIPsError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"}]}`))
	}))
	defer okServer.Close()

	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer errServer.Close()

	_, err := FetchGoogleCrawlerIPs(log, okServer.Client(), []string{okServer.URL, errServer.URL})
	if err == nil {
		t.Fatal("expected error when one endpoint returns non-200")
	}
}

func TestRefreshGoogleCrawlerIPs(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	g := NewGooglebotIPs()

	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}`))
	}))
	defer serverA.Close()

	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"203.0.113.0/25"},{"ipv6Prefix":"2001:db8::/32"}]}`))
	}))
	defer serverB.Close()

	count, err := RefreshGoogleCrawlerIPs(log, serverA.Client(), g, []string{serverA.URL, serverB.URL})
	if err != nil {
		t.Fatalf("RefreshGoogleCrawlerIPs failed: %v", err)
	}

	if count != 2 {
		t.Fatalf("expected reduced count 2, got %d", count)
	}

	if !g.Contains(net.ParseIP("203.0.113.9")) {
		t.Fatal("expected refreshed set to contain 203.0.113.9")
	}
	if !g.Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("expected refreshed set to contain 2001:db8::1")
	}
}

func TestRefreshGoogleCrawlerIPsError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	g := NewGooglebotIPs()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := RefreshGoogleCrawlerIPs(log, server.Client(), g, []string{server.URL})
	if err == nil {
		t.Fatal("expected refresh error")
	}
}
