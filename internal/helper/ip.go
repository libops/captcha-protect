package helper

import (
	"context"
	"net"
	"strings"
)

var (
	lookupAddrFunc = net.DefaultResolver.LookupAddr
	lookupIPFunc   = net.DefaultResolver.LookupIP
)

func IsIpExcluded(clientIP string, exemptIps []*net.IPNet) bool {
	ip := net.ParseIP(clientIP)
	for _, block := range exemptIps {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}

func IsIpGoodBot(clientIP string, goodBots []string) bool {
	return IsIpGoodBotContext(context.Background(), clientIP, goodBots)
}

func IsIpGoodBotContext(ctx context.Context, clientIP string, goodBots []string) bool {
	if len(goodBots) == 0 {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}

	// lookup the hostname for a given IP
	hostnames, err := lookupAddrFunc(ctx, clientIP)
	if err != nil || len(hostnames) == 0 {
		return false
	}

	for _, hostname := range hostnames {
		hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
		if !matchesGoodBotDomain(hostname, goodBots) {
			continue
		}

		// Resolve the PTR hostname forward to prevent forged reverse DNS records.
		resolvedIPs, err := lookupIPFunc(ctx, "ip", hostname)
		if err != nil {
			continue
		}
		for _, resolvedIP := range resolvedIPs {
			if resolvedIP.Equal(ip) {
				return true
			}
		}
	}

	return false
}

func matchesGoodBotDomain(hostname string, goodBots []string) bool {
	for _, bot := range goodBots {
		bot = strings.ToLower(strings.Trim(strings.TrimSpace(bot), "."))
		if bot != "" && (hostname == bot || strings.HasSuffix(hostname, "."+bot)) {
			return true
		}
	}
	return false
}
