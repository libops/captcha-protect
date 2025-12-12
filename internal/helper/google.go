package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// GooglebotIPs holds the list of Googlebot IP ranges, providing a thread-safe way to check if an IP is a Googlebot.
type GooglebotIPs struct {
	cidrs []*net.IPNet
	mu    sync.RWMutex
}

// googlebotIPsJSON is used to unmarshal the JSON response from Google's IP range endpoint.
type googlebotIPsJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// NewGooglebotIPs creates and initializes a new GooglebotIPs object.
func NewGooglebotIPs() *GooglebotIPs {
	return &GooglebotIPs{
		cidrs: make([]*net.IPNet, 0),
	}
}

// Update parses a slice of CIDR strings and replaces the existing IP ranges with the new ones.
// It logs an error for any CIDR string that fails to parse.
func (g *GooglebotIPs) Update(cidrs []string, log *slog.Logger) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.cidrs = make([]*net.IPNet, 0, len(cidrs))

	for _, s := range cidrs {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			log.Error("error parsing CIDR", "cidr", s, "err", err)

			continue
		}

		g.cidrs = append(g.cidrs, network)
	}
}

// Contains checks if the given IP address is within any of the stored Googlebot IP ranges.
func (g *GooglebotIPs) Contains(ip net.IP) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, network := range g.cidrs {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// FetchGooglebotIPs fetches the list of Googlebot IPs from Google's official endpoint,
// parses the JSON response, and returns a slice of CIDR strings.
func FetchGooglebotIPs(log *slog.Logger, httpClient *http.Client, url string) ([]string, error) {
	log.Debug("Fetching Googlebot IPs")

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Googlebot IP request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Googlebot IPs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Googlebot IPs, status code: %d", resp.StatusCode)
	}

	var ips googlebotIPsJSON
	err = json.NewDecoder(resp.Body).Decode(&ips)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Googlebot IPs: %w", err)
	}

	var cidrs []string
	for _, prefix := range ips.Prefixes {
		if prefix.IPv4Prefix != "" {
			cidrs = append(cidrs, prefix.IPv4Prefix)
		}
		if prefix.IPv6Prefix != "" {
			cidrs = append(cidrs, prefix.IPv6Prefix)
		}
	}

	return cidrs, nil
}
