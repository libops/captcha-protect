package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const rateLimit = 5
const rootSmokeIP = "192.0.2.10"
const app2SmokeIP = "198.51.100.10"

func main() {
	_ = os.Remove("./tmp/state.json")

	fmt.Println("Bringing traefik/nginx online")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	waitForService("http://localhost/app2")

	fmt.Println("Testing Traefik plugin smoke path...")
	assertProtectedRoute(rootSmokeIP, "http://localhost", "http://localhost/challenge?destination=%2F")
	assertNoRedirect(rootSmokeIP, "http://localhost/node/123/manifest")
	assertNoRedirect(rootSmokeIP, "http://localhost/oai/request?foo=bar")
	assertProtectedRoute(app2SmokeIP, "http://localhost/app2", "http://localhost/challenge?destination=%2Fapp2")

	_ = os.Remove("./tmp/state.json")
	fmt.Println("✓ Traefik plugin smoke test passed")
}

func waitForService(url string) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) // #nosec G107 -- CI smoke test only calls fixed localhost URLs.
		if err == nil && resp.StatusCode < 500 {
			_ = resp.Body.Close()
			return
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		fmt.Println("waiting for traefik/nginx to come online...")
		time.Sleep(1 * time.Second)
	}

	slog.Error("Timed out waiting for service", "url", url)
	os.Exit(1)
}

func assertProtectedRoute(ip, url, expectedURL string) {
	for i := 0; i < rateLimit; i++ {
		assertNoRedirect(ip, url)
	}

	output, err := httpRequest(ip, url)
	if err != nil {
		slog.Error("Request failed", "ip", ip, "url", url, "err", err)
		os.Exit(1)
	}
	if output != expectedURL {
		slog.Error("Expected protected route to redirect", "ip", ip, "url", url, "output", output, "expected", expectedURL)
		os.Exit(1)
	}
}

func assertNoRedirect(ip, url string) {
	output, err := httpRequest(ip, url)
	if err != nil {
		slog.Error("Request failed", "ip", ip, "url", url, "err", err)
		os.Exit(1)
	}
	if output != "" {
		slog.Error("Unexpected redirect", "ip", ip, "url", url, "output", output)
		os.Exit(1)
	}
}

func httpRequest(ip, url string) (string, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Forwarded-For", ip)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	location, err := resp.Location()
	if err != nil {
		if err == http.ErrNoLocation {
			return "", nil
		}
		return "", err
	}

	return strings.TrimSpace(location.String()), nil
}

func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...) // #nosec G204 -- CI smoke test invokes fixed docker compose commands.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), fmt.Sprintf("RATE_LIMIT=%d", rateLimit))

	if traefikTag := os.Getenv("TRAEFIK_TAG"); traefikTag != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("TRAEFIK_TAG=%s", traefikTag))
	}

	if err := cmd.Run(); err != nil {
		slog.Error("Command failed", "err", err)
		os.Exit(1)
	}
}
