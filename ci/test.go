package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	googleCIDRs, err := helper.FetchGoogleCrawlerIPs(log, http.DefaultClient, helper.GoogleCrawlerIPRangeURLs)
	if err != nil {
		slog.Error("unable to fetch google crawler ips", "err", err)
		os.Exit(1)
	}

	_ips := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	_ips = append(_ips, googleCIDRs...)
	for _, ip := range _ips {
		parsedIp := parseCIDR(ip)
		exemptIps = append(exemptIps, parsedIp)
	}

	fmt.Printf("Checking rate limit %d\n", rateLimit)

	fmt.Printf("Generating %d IPs\n", numIPs)
	ips := generateUniquePublicIPs(numIPs)

	statePath, err := prepareStateFile(0o777, 0o666)
	if err != nil {
		slog.Error("Failed to prepare state file", "statePath", statePath, "err", err)
		os.Exit(1)
	}

	fmt.Println("Bringing traefik/nginx online")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	waitForService("http://localhost/app2")
	waitForGoogleExemptionReady(googleCIDRs)

	fmt.Printf("Making sure %d attempt(s) pass\n", rateLimit)
	runParallelChecks(ips, rateLimit, "http://localhost")

	statePath, err = waitForStateFile(30 * time.Second)
	if err != nil {
		slog.Error("State file was not created in time", "err", err)
		os.Exit(1)
	}
	runCommand("jq", ".", statePath)

	fmt.Printf("Making sure attempt #%d causes a redirect to the challenge page\n", rateLimit+1)
	ensureRedirect(ips, "http://localhost")

	fmt.Println("\nTesting state sharing between nginx instances...")
	time.Sleep(cp.StateSaveInterval + cp.StateSaveJitter + (1 * time.Second))

	testStateSharing(ips)
	testGoogleBotGetsThrough(googleCIDRs)

	runCommand("docker", "container", "stats", "--no-stream")

	// now restart the containers and make sure the previous state reloaded
	runCommand("docker", "compose", "down")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	time.Sleep(10 * time.Second)
	checkStateReload()

	runCommand("rm", "-f", statePath)

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

func runParallelChecks(ips []string, rateLimit int, url string) {
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
				output := httpRequest(ip, url)
				if output != "" {
					slog.Error("Unexpected output", "ip", ip, "output", output)
					os.Exit(1)

				}
			}(ip)
		}
	}

	wg.Wait()
}

func ensureRedirect(ips []string, url string) {
	expectedURL := url + "/challenge?destination=%2F"
	if url != "http://localhost" {
		// For /app2, the destination should be the app2 path
		expectedURL = "http://localhost/challenge?destination=%2Fapp2"
	}

	for _, ip := range ips {
		fmt.Printf("Checking %s\n", ip)
		output := httpRequest(ip, url)

		if output != expectedURL {
			slog.Error("Unexpected output", "ip", ip, "output", output, "expected", expectedURL)
			os.Exit(1)
		}

		fmt.Printf("Got a redirect! %s\n", output)
	}
}

func testStateSharing(ips []string) {
	// Use first IP to test state sharing
	testIP := ips[0]

	fmt.Printf("Testing with IP: %s\n", testIP)

	// The IP should already be at rate limit from previous tests on localhost/
	// Now verify it's also rate limited on localhost/app2 (shared state)
	fmt.Println("Verifying IP is rate limited on /app2 (state should be shared)...")
	output := httpRequest(testIP, "http://localhost/app2")
	expectedURL := "http://localhost/challenge?destination=%2Fapp2"

	if output != expectedURL {
		slog.Error("State NOT shared between instances!", "ip", testIP, "output", output, "expected", expectedURL)
		os.Exit(1)
	}

	fmt.Println("✓ State is correctly shared between nginx instances!")
}

func httpRequest(ip, url string) string {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Capture the redirect URL and stop following it
			if len(via) > 0 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
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
	runCommandWithEnv(nil, name, args...)
}

func runCommandWithEnv(env map[string]string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(cmd.Env, fmt.Sprintf("RATE_LIMIT=%d", rateLimit))
	cmd.Env = append(cmd.Env, fmt.Sprintf("PATH=%s", os.Getenv("PATH")))

	tt := os.Getenv("TRAEFIK_TAG")
	if tt != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TRAEFIK_TAG=%s", tt))
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
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

func getIPFromCIDR(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	// For IPv4, increment the IP to get a usable host address
	if ip.To4() != nil {
		// Clone the IP to avoid modifying the original
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)

		for i := len(newIP) - 1; i >= 0; i-- {
			newIP[i]++
			if newIP[i] > 0 {
				break
			}
		}

		// If the new IP is the broadcast address, we can't use it.
		// This is a simplistic check, and might not cover all cases for small subnets.
		// A more robust solution might be needed for very small CIDR ranges.
		if !ipnet.Contains(newIP) {
			// This can happen for /31 or /32. For now, we just return the network address.
			return ip.String(), nil
		}
		// make sure we don't have a broadcast address
		last_ip := make(net.IP, len(ipnet.IP))
		copy(last_ip, ipnet.IP)
		for i := 0; i < len(ipnet.Mask); i++ {
			last_ip[i] |= ^ipnet.Mask[i]
		}
		if newIP.Equal(last_ip) {
			return ip.String(), nil
		}

		return newIP.String(), nil
	}

	// For IPv6, we can usually just use the network address.
	return ip.String(), nil
}

func testGoogleBotGetsThrough(googleCIDRs []string) {
	fmt.Println("\nTesting GoogleBot exemption...")

	if len(googleCIDRs) == 0 {
		slog.Warn("No Google CIDRs found, skipping test")
		return
	}

	// Pick a Google IP
	googleIP, err := getIPFromCIDR(googleCIDRs[len(googleCIDRs)-1])
	if err != nil {
		slog.Error("Failed to get an IP from google CIDR", "err", err)
		os.Exit(1)
	}

	var output string // Declare output once here

	fmt.Printf("Checking GoogleBot IP %s without params - should always pass (making %d requests)\n", googleIP, rateLimit+1)
	for i := 0; i < rateLimit+1; i++ {
		output = httpRequest(googleIP, "http://localhost") // Assign value to the already declared 'output'
		if output != "" {
			slog.Error(fmt.Sprintf("GoogleBot with no params was challenged on request #%d", i+1), "ip", googleIP, "output", output)
			os.Exit(1)
		}
	}
	fmt.Printf("✓ GoogleBot with no params passed %d requests successfully\n", rateLimit+1)

	// now restart with PROTECT_PARAMETERS=true and test again with params
	fmt.Println("\nRestarting traefik with PROTECT_PARAMETERS=true")
	runCommand("docker", "compose", "down")
	runCommandWithEnv(map[string]string{"PROTECT_PARAMETERS": "true"}, "docker", "compose", "up", "-d")
	waitForService("http://localhost")
	waitForService("http://localhost/app2")

	// Prime the rate limiter for the GoogleBot IP with parameters
	fmt.Printf("Priming rate limiter for GoogleBot IP %s with params (%d requests)\n", googleIP, rateLimit)
	for i := range rateLimit {
		output = httpRequest(googleIP, "http://localhost/?foo=bar") // Assign value
		if output != "" {
			slog.Error(fmt.Sprintf("GoogleBot with params was challenged prematurely on request #%d", i+1), "ip", googleIP, "output", output)
			os.Exit(1)
		}
	}
	fmt.Printf("✓ Rate limiter primed for GoogleBot IP %s\n", googleIP)

	fmt.Printf("Checking GoogleBot IP %s with params (request #%d) - should be challenged\n", googleIP, rateLimit+1)
	output = httpRequest(googleIP, "http://localhost/?foo=bar") // Assign value
	expectedURL := "http://localhost/challenge?destination=%2F%3Ffoo%3Dbar"
	if output != expectedURL {
		slog.Error("GoogleBot with params was not challenged", "ip", googleIP, "output", output, "expected", expectedURL)
		os.Exit(1)
	}
	fmt.Println("✓ GoogleBot with params was challenged")

	// set things back to normal for other tests
	runCommand("docker", "compose", "down")
}

func waitForGoogleExemptionReady(googleCIDRs []string) {
	googleIP, err := firstUsableIPv4FromCIDRs(googleCIDRs)
	if err != nil {
		slog.Warn("Unable to select Google IP for readiness check; skipping warmup", "err", err)
		return
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for i := 0; i < rateLimit+1; i++ {
			if output := httpRequest(googleIP, "http://localhost"); output != "" {
				ready = false
				break
			}
		}
		if ready {
			fmt.Printf("Google exemption is active for %s\n", googleIP)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}

	slog.Error("Timed out waiting for Google crawler IP exemption to become active", "googleIP", googleIP)
	os.Exit(1)
}

func firstUsableIPv4FromCIDRs(cidrs []string) (string, error) {
	for _, cidr := range cidrs {
		ip, err := getIPFromCIDR(cidr)
		if err != nil {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() != nil {
			return ip, nil
		}
	}

	return "", fmt.Errorf("no usable IPv4 found in CIDR list")
}

func waitForStateFile(timeout time.Duration) (string, error) {
	paths := []string{
		filepath.Join("tmp", "state.json"),
		filepath.Join("ci", "tmp", "state.json"),
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range paths {
			info, err := os.Stat(p)
			if err == nil && !info.IsDir() {
				return p, nil
			}
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("failed to stat %s: %w", p, err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("state file not found; checked: %s", strings.Join(paths, ", "))
}

func prepareStateFile(dirMode, fileMode os.FileMode) (string, error) {
	p := filepath.Join("tmp", "state.json")

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return "", fmt.Errorf("failed to create state dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return "", fmt.Errorf("failed to chmod state dir %s: %w", dir, err)
	}

	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, fileMode)
	if err != nil {
		return "", fmt.Errorf("failed to open state file %s: %w", p, err)
	}
	_ = f.Close()
	if err := os.Chmod(p, fileMode); err != nil {
		return "", fmt.Errorf("failed to chmod state file %s: %w", p, err)
	}

	return p, nil
}
