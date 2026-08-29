package helper

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestFetchCommonCrawlIPsVerifiesEachIPv4Address(t *testing.T) {
	originalLookupAddr := lookupAddrFunc
	originalLookupIP := lookupIPFunc
	defer func() {
		lookupAddrFunc = originalLookupAddr
		lookupIPFunc = originalLookupIP
	}()

	lookupAddrFunc = func(_ context.Context, address string) ([]string, error) {
		hostnames := map[string]string{
			"203.0.113.0": "crawl-0.commoncrawl.org.",
			"203.0.113.1": "unrelated.example.org.",
			"203.0.113.2": "crawl-2.commoncrawl.org.",
			"203.0.113.3": "crawl-3.commoncrawl.org.",
		}
		return []string{hostnames[address]}, nil
	}
	lookupIPFunc = func(_ context.Context, _ string, host string) ([]net.IP, error) {
		addresses := map[string]string{
			"crawl-0.commoncrawl.org": "203.0.113.0",
			"crawl-2.commoncrawl.org": "203.0.113.2",
			// A matching PTR without a forward match must not be trusted.
			"crawl-3.commoncrawl.org": "198.51.100.3",
		}
		return []net.IP{net.ParseIP(addresses[host])}, nil
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"prefixes": [
				{"ipv4Prefix":"203.0.113.0/30"},
				{"ipv6Prefix":"2001:db8::/56"}
			]
		}`))
	}))
	defer server.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	got, err := FetchCommonCrawlIPs(context.Background(), log, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.0/32", "203.0.113.2/32", "2001:db8::/56"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Common Crawl CIDRs = %v, want %v", got, want)
	}
}

func TestFetchCommonCrawlIPsRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "non-200", statusCode: http.StatusBadGateway, body: `{}`},
		{name: "invalid JSON", statusCode: http.StatusOK, body: `{`},
		{name: "empty ranges", statusCode: http.StatusOK, body: `{"prefixes":[]}`},
		{name: "invalid CIDR", statusCode: http.StatusOK, body: `{"prefixes":[{"ipv4Prefix":"not-a-cidr"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			if _, err := FetchCommonCrawlIPs(context.Background(), slog.Default(), server.Client(), server.URL); err == nil {
				t.Fatal("expected invalid response to fail")
			}
		})
	}
}

func TestRefreshCommonCrawlIPsKeepsLastGoodSetOnError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ips := NewCommonCrawlIPs()
	ips.Update([]string{"203.0.113.10/32"}, log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	if _, err := RefreshCommonCrawlIPs(context.Background(), log, server.Client(), ips, server.URL); err == nil {
		t.Fatal("expected refresh error")
	}
	if !ips.Contains(net.ParseIP("203.0.113.10")) {
		t.Fatal("expected failed refresh to retain the previous ranges")
	}
}
