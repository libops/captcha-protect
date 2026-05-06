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

func main() {
	_ = os.Remove("./tmp/state.json")

	fmt.Println("Bringing traefik/nginx online")
	runCommand("docker", "compose", "up", "-d")
	waitForService("http://localhost")
	waitForService("http://localhost/app2")

	fmt.Println("Testing Traefik plugin smoke path...")
	assertProtectedRoute("107.198.130.166", "http://localhost", "http://localhost/challenge?destination=%2F")
	assertNoRedirect("107.198.130.166", "http://localhost/node/123/manifest")
	assertNoRedirect("107.198.130.166", "http://localhost/oai/request?foo=bar")
	assertProtectedRoute("108.198.130.167", "http://localhost/app2", "http://localhost/challenge?destination=%2Fapp2")

	_ = os.Remove("./tmp/state.json")
	fmt.Println("✓ Traefik plugin smoke test passed")
}

func waitForService(url string) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
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

	output := httpRequest(ip, url)
	if output != expectedURL {
		slog.Error("Expected protected route to redirect", "ip", ip, "url", url, "output", output, "expected", expectedURL)
		os.Exit(1)
	}
}

func assertNoRedirect(ip, url string) {
	output := httpRequest(ip, url)
	if output != "" {
		slog.Error("Unexpected redirect", "ip", ip, "url", url, "output", output)
		os.Exit(1)
	}
}

func httpRequest(ip, url string) string {
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

func runCommand(name string, args ...string) {
	cmd := exec.Command(name, args...)
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
