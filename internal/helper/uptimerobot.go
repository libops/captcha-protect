package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"
)

const maxUptimeRobotIPResponseSize = 1 << 20

// UptimeRobotIPRangeURL is the official UptimeRobot checker range endpoint.
var UptimeRobotIPRangeURL = "https://api.uptimerobot.com/meta/ips"

// UptimeRobotIPs is a thread-safe set of UptimeRobot IP ranges.
type UptimeRobotIPs struct {
	ranges *GooglebotIPs
}

// NewUptimeRobotIPs creates an empty UptimeRobot IP range set.
func NewUptimeRobotIPs() *UptimeRobotIPs {
	return &UptimeRobotIPs{
		ranges: NewGooglebotIPs(),
	}
}

// Update parses a slice of CIDR strings and replaces the existing IP ranges with the new ones.
func (u *UptimeRobotIPs) Update(cidrs []string, log *slog.Logger) {
	u.ranges.Update(cidrs, log)
}

// Contains checks if the given IP address is within any stored UptimeRobot IP range.
func (u *UptimeRobotIPs) Contains(ip net.IP) bool {
	return u.ranges.Contains(ip)
}

type uptimeRobotIPsJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ip_prefix"`
		IPv6Prefix string `json:"ipv6_prefix"`
	} `json:"prefixes"`
}

// FetchUptimeRobotIPs fetches and validates UptimeRobot's published checker IP ranges.
func FetchUptimeRobotIPs(ctx context.Context, httpClient *http.Client, endpoint string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UptimeRobot IP request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch UptimeRobot IPs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch UptimeRobot IPs, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUptimeRobotIPResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read UptimeRobot IPs: %w", err)
	}
	if len(body) > maxUptimeRobotIPResponseSize {
		return nil, fmt.Errorf("UptimeRobot IP response exceeds %d bytes", maxUptimeRobotIPResponseSize)
	}

	var payload uptimeRobotIPsJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode UptimeRobot IPs: %w", err)
	}

	cidrs := make([]string, 0, len(payload.Prefixes))
	for _, prefix := range payload.Prefixes {
		for _, cidr := range []string{prefix.IPv4Prefix, prefix.IPv6Prefix} {
			if cidr == "" {
				continue
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return nil, fmt.Errorf("invalid UptimeRobot CIDR %q: %w", cidr, err)
			}
			cidrs = append(cidrs, cidr)
		}
	}
	if len(cidrs) == 0 {
		return nil, fmt.Errorf("UptimeRobot IP response contained no ranges")
	}

	return cidrs, nil
}

// RefreshUptimeRobotIPs atomically replaces the active ranges after a successful fetch.
func RefreshUptimeRobotIPs(parent context.Context, log *slog.Logger, httpClient *http.Client, target *UptimeRobotIPs, endpoint string) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	cidrs, err := FetchUptimeRobotIPs(ctx, httpClient, endpoint)
	if err != nil {
		return 0, err
	}
	cidrs = ReduceCIDRs(cidrs, log)
	target.Update(cidrs, log)

	return len(cidrs), nil
}
