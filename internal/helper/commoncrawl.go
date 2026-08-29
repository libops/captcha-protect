package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

const (
	maxCommonCrawlIPResponseSize = 1 << 20
	commonCrawlDomain            = "commoncrawl.org"
)

// CommonCrawlIPRangeURL is the official CCBot range endpoint.
var CommonCrawlIPRangeURL = "https://index.commoncrawl.org/ccbot.json"

// CommonCrawlIPs is a thread-safe set of verified Common Crawl IP ranges.
type CommonCrawlIPs struct {
	ranges *GooglebotIPs
}

// NewCommonCrawlIPs creates an empty Common Crawl IP range set.
func NewCommonCrawlIPs() *CommonCrawlIPs {
	return &CommonCrawlIPs{
		ranges: NewGooglebotIPs(),
	}
}

// Update parses a slice of CIDR strings and replaces the existing IP ranges.
func (c *CommonCrawlIPs) Update(cidrs []string, log *slog.Logger) {
	c.ranges.Update(cidrs, log)
}

// Contains checks if the given IP address is within the verified Common Crawl ranges.
func (c *CommonCrawlIPs) Contains(ip net.IP) bool {
	return c.ranges.Contains(ip)
}

type commonCrawlIPsJSON struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

// FetchCommonCrawlIPs fetches CCBot ranges and expands IPv4 ranges into
// individually FCrDNS-verified addresses. Published IPv6 ranges are retained.
func FetchCommonCrawlIPs(ctx context.Context, log *slog.Logger, httpClient *http.Client, endpoint string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Common Crawl IP request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Common Crawl IPs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch Common Crawl IPs, status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCommonCrawlIPResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Common Crawl IPs: %w", err)
	}
	if len(body) > maxCommonCrawlIPResponseSize {
		return nil, fmt.Errorf("response from Common Crawl exceeds %d bytes", maxCommonCrawlIPResponseSize)
	}

	var payload commonCrawlIPsJSON
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to decode Common Crawl IPs: %w", err)
	}
	if len(payload.Prefixes) == 0 {
		return nil, fmt.Errorf("response from Common Crawl contained no IP ranges")
	}

	verifiedCIDRs := make([]string, 0, len(payload.Prefixes))
	for _, item := range payload.Prefixes {
		for _, cidr := range []string{item.IPv4Prefix, item.IPv6Prefix} {
			if cidr == "" {
				continue
			}

			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid Common Crawl CIDR %q: %w", cidr, err)
			}
			prefix = prefix.Masked()

			if prefix.Addr().Is6() {
				verifiedCIDRs = append(verifiedCIDRs, prefix.String())
				continue
			}
			if !prefix.Addr().Is4() {
				return nil, fmt.Errorf("unsupported Common Crawl CIDR %q", cidr)
			}

			for ip := prefix.Addr(); ip.IsValid() && prefix.Contains(ip); ip = ip.Next() {
				if err := ctx.Err(); err != nil {
					return nil, fmt.Errorf("verification of Common Crawl IPv4 addresses canceled: %w", err)
				}

				if IsIpGoodBotContext(ctx, ip.String(), []string{commonCrawlDomain}) {
					verifiedCIDRs = append(verifiedCIDRs, netip.PrefixFrom(ip, 32).String())
					continue
				}

				if log != nil {
					log.Warn("Excluded unverified Common Crawl IPv4 address", "ip", ip.String())
				}
			}
		}
	}

	return ReduceCIDRs(verifiedCIDRs, log), nil
}

// RefreshCommonCrawlIPs atomically replaces the active ranges after a successful fetch.
func RefreshCommonCrawlIPs(parent context.Context, log *slog.Logger, httpClient *http.Client, target *CommonCrawlIPs, endpoint string) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()

	cidrs, err := FetchCommonCrawlIPs(ctx, log, httpClient, endpoint)
	if err != nil {
		return 0, err
	}
	target.Update(cidrs, log)

	return len(cidrs), nil
}
