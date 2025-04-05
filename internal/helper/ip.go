package helper

import (
	"net"
	"strings"
)

var (
	lookupAddrFunc = net.LookupAddr
	lookupIPFunc   = net.LookupIP
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
	if len(goodBots) == 0 {
		return false
	}

	// lookup the hostname for a given IP
	hostname, err := lookupAddrFunc(clientIP)
	if err != nil || len(hostname) == 0 {
		return false
	}

	// then nslookup that hostname to avoid spoofing
	resolvedIP, err := lookupIPFunc(hostname[0])
	if err != nil || len(resolvedIP) == 0 || resolvedIP[0].String() != clientIP {
		return false
	}

	// get the sld
	// will be like 194.114.135.34.bc.googleusercontent.com.
	// notice the trailing period
	parts := strings.Split(hostname[0], ".")
	l := len(parts)
	if l < 3 {
		return false
	}
	tld := parts[l-2]
	domain := parts[l-3] + "." + tld

	for _, bot := range goodBots {
		if domain == bot {
			return true
		}
	}

	return false
}
