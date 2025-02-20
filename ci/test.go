package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
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
)

var rateLimit = 5
var exemptIps []*net.IPNet

const numIPs = 100
const parallelism = 10
const expectedRedirectURL = "http://localhost/challenge?destination=%2F"

func main() {
	_ips := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	for _, ip := range _ips {
		parsedIp, err := cp.ParseCIDR(ip)
		if err != nil {
			slog.Error("error parsing cidr", "ip", ip, "err", err)
			os.Exit(1)
		}
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

	fmt.Println("Sleeping for 3m")
	time.Sleep(3 * time.Minute)
	fmt.Println("Making sure one attempt passes after 2m window")
	runParallelChecks(ips, 1)

	fmt.Println("All good 🚀")

	runCommand("docker", "container", "stats", "--no-stream")
	runCommand("docker", "compose", "down")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	checkStateReload()

	runCommand("rm", "tmp/state.json")

}

func generateUniquePublicIPs(n int) []string {
	ipSet := make(map[string]struct{})
	var ips []string
	config := cp.CreateConfig()

	for len(ips) < n {
		ip := randomPublicIP(config)
		ip, ipRange := cp.ParseIp(ip, 16, 64)
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

		if !cp.IsIpExcluded(ip, exemptIps) && !cp.IsIpGoodBot(ip, config.GoodBots) {
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
					log.Fatalf("Unexpected output for %s: %s", ip, output)
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
			log.Fatalf("Unexpected output for %s: %s", ip, output)
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
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("X-Forwarded-For", ip)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Get redirect URL from response
	location, err := resp.Location()
	if err != nil {
		if err == http.ErrNoLocation {
			return ""
		}
		log.Fatalf("Failed to get redirect URL: %v", err)
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
	if err := cmd.Run(); err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func checkStateReload() {
	resp, err := http.Get("http://localhost/captcha-protect/stats")
	if err != nil {
		log.Fatalf("Failed to make GET request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	var jsonResponse map[string]interface{}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	bots, exists := jsonResponse["bots"]
	if !exists {
		log.Fatalf("Key 'bots' not found in JSON response")
	}
	botsMap, ok := bots.(map[string]interface{})
	if !ok {
		log.Fatalf("'bots' is not an array")
	}

	if len(botsMap) != numIPs {
		log.Fatalf("Expected %d bots, but got %d", numIPs, len(botsMap))
	}
}
