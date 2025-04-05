package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	cp "github.com/libops/captcha-protect"
	"github.com/libops/captcha-protect/internal/helper"
)

var (
	rateLimit = 5
	exemptIps []*net.IPNet
)

const numIPs = 100
const parallelism = 10
const expectedRedirectURL = "http://localhost/challenge?destination=%2F"

func main() {
	_ips := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	for _, ip := range _ips {
		parsedIp := parseCIDR(ip)
		exemptIps = append(exemptIps, parsedIp)
	}

	fmt.Printf("Checking rate limit %d\n", rateLimit)

	fmt.Printf("Generating %d IPs\n", numIPs)
	ips := generateUniquePublicIPs(numIPs)

	fmt.Println("Bringing traefik/nginx online")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")

	fmt.Printf("Making sure %d attempt(s) pass\n", rateLimit)
	runParallelChecks(ips, rateLimit)

	fmt.Printf("Making sure attempt #%d causes a redirect to the challenge page\n", rateLimit+1)
	ensureRedirect(ips)

	fmt.Println("Sleeping for 2m")
	time.Sleep(125 * time.Second)
	fmt.Println("Making sure one attempt passes after 2m window")
	runParallelChecks(ips, 1)
	fmt.Println("All good 🚀")

	// make sure the state has time to save
	fmt.Println("Waiting for state to save")
	runCommand("jq", ".", "tmp/state.json")
	time.Sleep(80 * time.Second)
	runCommand("jq", ".", "tmp/state.json")

	runCommand("docker", "container", "stats", "--no-stream")

	// now restart the containers and make sure the previous state reloaded
	runCommand("docker", "compose", "down")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	time.Sleep(10 * time.Second)
	checkStateReload()

	runCommand("rm", "tmp/state.json")

}

func generateUniquePublicIPs(n int) []string {
	ipSet := make(map[string]struct{})
	var ips []string
	config := cp.CreateConfig()
	bc := &cp.CaptchaProtect{}
	bc.SetExemptIps(exemptIps)
	err := bc.SetIpv4Mask(16)
	if err != nil {
		slog.Error("unable to set ipv4 mask")
		os.Exit(1)
	}

	err = bc.SetIpv6Mask(64)
	if err != nil {
		slog.Error("unable to set ipv6 mask")
		os.Exit(1)
	}

	for len(ips) < n {
		ip := randomPublicIP(config)
		ip, ipRange := bc.ParseIp(ip)
		if _, exists := ipSet[ipRange]; !exists {
			ipSet[ipRange] = struct{}{}
			ips = append(ips, ip)
		}
	}

	return ips
}

func randomPublicIP(config *cp.Config) string {
	for {
		ip := fmt.Sprintf("%d.%d.%d.%d",
			rand.Intn(255)+1,
			rand.Intn(255),
			rand.Intn(255),
			rand.Intn(254)+1,
		)

		if !helper.IsIpExcluded(ip, exemptIps) && !helper.IsIpGoodBot(ip, config.GoodBots) {
			return ip
		}
	}
}

func waitForService(url string) {
	for {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			time.Sleep(5 * time.Second) // Give it time to stabilize
			return
		}
		fmt.Println("waiting for traefik/nginx to come online...")
		time.Sleep(1 * time.Second)
	}
}

func runParallelChecks(ips []string, rateLimit int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallelism)

	for i := 0; i < rateLimit; i++ {
		for _, ip := range ips {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string) {
				defer wg.Done()
				defer func() { <-sem }()

				fmt.Printf("Checking %s\n", ip)
				output := httpRequest(ip)
				if output != "" {
					slog.Error("Unexpected output", "ip", ip, "output", output)
					os.Exit(1)

				}
			}(ip)
		}
	}

	wg.Wait()
}

func ensureRedirect(ips []string) {
	for _, ip := range ips {
		fmt.Printf("Checking %s\n", ip)
		output := httpRequest(ip)

		if output != expectedRedirectURL {
			slog.Error("Unexpected output", "ip", ip, "output", output)
			os.Exit(1)
		}

		fmt.Printf("Got a redirect! %s\n", output)
	}
}

func httpRequest(ip string) string {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Capture the redirect URL and stop following it
			if len(via) > 0 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		slog.Error("Failed to create request", "err", err)
		os.Exit(1)
	}
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Request failed", "err", err)
		os.Exit(1)

	}
	defer resp.Body.Close()

	// Get redirect URL from response
	location, err := resp.Location()
	if err != nil {
		if err == http.ErrNoLocation {
			return ""
		}
		slog.Error("Failed to get redirect URL", "err", err)
		os.Exit(1)

	}

	return strings.TrimSpace(location.String())
}

// runCommand runs a shell command.
func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(cmd.Env, fmt.Sprintf("RATE_LIMIT=%d", rateLimit))
	cmd.Env = append(cmd.Env, fmt.Sprintf("PATH=%s", os.Getenv("PATH")))

	tt := os.Getenv("TRAEFIK_TAG")
	if tt != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TRAEFIK_TAG=%s", tt))
	}
	if err := cmd.Run(); err != nil {
		slog.Error("Command failed", "err", err)
		os.Exit(1)
	}
}

func checkStateReload() {
	resp, err := http.Get("http://localhost/captcha-protect/stats")
	if err != nil {
		slog.Error("Failed to make GET request", "err", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read response body", "err", err)
		os.Exit(1)

	}
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		slog.Error("Failed to unmarshal JSON", "err", err)
		os.Exit(1)

	}
	bots, exists := jsonResponse["bots"]
	if !exists {
		slog.Error("Key 'bots' not found in JSON response")
		os.Exit(1)
	}
	botsMap, ok := bots.(map[string]interface{})
	if !ok {
		slog.Error("'bots' is not an array")
		os.Exit(1)
	}

	if len(botsMap) != numIPs {
		slog.Error("Unexpected number of bots", "expected", numIPs, "received", len(botsMap))
		os.Exit(1)
	}

	slog.Info("State reloaded successfully!")
}

func parseCIDR(cidr string) *net.IPNet {
	_, block, err := net.ParseCIDR(cidr)
	if err != nil {
		slog.Error("Failed to parse CIDR", "cidr", cidr, "err", err)
	}
	return block
}
