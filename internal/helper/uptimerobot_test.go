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

func TestFetchUptimeRobotIPs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"prefixes": [
				{"ip_prefix":"203.0.113.10/32","service":"checker"},
				{"ipv6_prefix":"2001:db8::10/128","service":"checker"}
			]
		}`))
	}))
	defer server.Close()

	got, err := FetchUptimeRobotIPs(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.10/32", "2001:db8::10/128"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UptimeRobot CIDRs = %v, want %v", got, want)
	}
}

func TestFetchUptimeRobotIPsRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "non-200", statusCode: http.StatusBadGateway, body: `{}`},
		{name: "invalid JSON", statusCode: http.StatusOK, body: `{`},
		{name: "empty ranges", statusCode: http.StatusOK, body: `{"prefixes":[]}`},
		{name: "invalid CIDR", statusCode: http.StatusOK, body: `{"prefixes":[{"ip_prefix":"not-a-cidr"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			if _, err := FetchUptimeRobotIPs(context.Background(), server.Client(), server.URL); err == nil {
				t.Fatal("expected invalid response to fail")
			}
		})
	}
}

func TestRefreshUptimeRobotIPsKeepsLastGoodSetOnError(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ips := NewUptimeRobotIPs()
	ips.Update([]string{"203.0.113.10/32"}, log)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer server.Close()

	if _, err := RefreshUptimeRobotIPs(context.Background(), log, server.Client(), ips, server.URL); err == nil {
		t.Fatal("expected refresh error")
	}
	if !ips.Contains(net.ParseIP("203.0.113.10")) {
		t.Fatal("expected failed refresh to retain the previous ranges")
	}
}

func TestFetchUptimeRobotIPsHonorsCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := FetchUptimeRobotIPs(ctx, server.Client(), server.URL)
		done <- err
	}()
	<-requestStarted
	cancel()

	if err := <-done; err == nil {
		t.Fatal("expected canceled fetch to fail")
	}
}
