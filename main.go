package captcha_protect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"

	lru "github.com/patrickmn/go-cache"
)

type Config struct {
	RateLimit         uint          `json:"rateLimit"`
	Window            time.Duration `json:"window"`
	IPv4SubnetMask    int           `json:"ipv4subnetMask"`
	IPv6SubnetMask    int           `json:"ipv6subnetMask"`
	IPForwardedHeader string        `json:"ipForwardedHeader"`
	ProtectParameters string        `json:"protectedParameters"`
	ProtectRoutes     []string      `json:"protectRoutes"`
	GoodBots          []string      `json:"goodBots"`
	ExemptIPs         []string      `json:"exemptIps"`
	ChallengeURL      string        `json:"challengeURL"`
	ChallengeTmpl     string        `json:"challengeTmpl"`
	CaptchaProvider   string        `json:"captchaProvider"`
	SiteKey           string        `json:"siteKey"`
	SecretKey         string        `json:"secretKey"`
	EnableStatsPage   string        `json:"enableStatsPage"`
	LogLevel          string        `json:"loglevel,omitempty"`
}

type CaptchaProtect struct {
	next          http.Handler
	name          string
	config        *Config
	rateCache     *lru.Cache
	verifiedCache *lru.Cache
	botCache      *lru.Cache
	captchaConfig CaptchaConfig
	exemptIps     []*net.IPNet
}

type CaptchaConfig struct {
	js       string
	key      string
	validate string
}

type captchaResponse struct {
	Success bool `json:"success"`
}

func CreateConfig() *Config {
	return &Config{
		RateLimit:         20,
		Window:            24 * time.Hour,
		IPv4SubnetMask:    16,
		IPv6SubnetMask:    64,
		IPForwardedHeader: "",
		ProtectParameters: "false",
		ProtectRoutes: []string{
			"/",
		},
		GoodBots: []string{
			"duckduckgo.com",
			"kagibot.org",
			"googleusercontent.com",
			"google.com",
			"googlebot.com",
			"msn.com",
			"openalex.org",
			"archive.org",
			"linkedin.com",
			"facebook.com",
			"instagram.com",
			"twitter.com",
			"x.com",
			"apple.com",
		},
		ChallengeURL:    "/challenge",
		EnableStatsPage: "false",
		LogLevel:        "INFO",
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	logLevel, err := log.ParseLevel(config.LogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to set log level: %w", err)
	}
	log.Default().Level = logLevel

	if _, err := os.Stat(config.ChallengeTmpl); os.IsNotExist(err) {
		return nil, fmt.Errorf("template file does not exist: %s", config.ChallengeTmpl)
	} else if err != nil {
		return nil, fmt.Errorf("error check for template file %s: %v", config.ChallengeTmpl, err)
	}

	// always exempt local IPs
	exemptIPs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	// include IPs from config
	exemptIPs = append(exemptIPs, config.ExemptIPs...)

	// transform exempt IPs into what go can easily parse
	var ips []*net.IPNet
	for _, ip := range exemptIPs {
		parsedIp, err := ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", ip, err)
		}
		ips = append(ips, parsedIp)
	}

	bc := CaptchaProtect{
		next:      next,
		name:      name,
		config:    config,
		rateCache: lru.New(config.Window, 10*time.Minute),
		botCache:  lru.New(config.Window, 10*time.Minute),
		// allow good IPs to pass through for ten days
		verifiedCache: lru.New(240*time.Hour, 1*time.Hour),
		exemptIps:     ips,
	}

	// set the captcha config based on the provider
	// thanks to https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/4708d76854c7ae95fa7313c46fbe21959be2fff1/pkg/captcha/captcha.go#L39-L55
	// for the struct/idea
	if config.CaptchaProvider == "hcaptcha" {
		bc.captchaConfig = CaptchaConfig{
			js:       "https://hcaptcha.com/1/api.js",
			key:      "h-captcha",
			validate: "https://api.hcaptcha.com/siteverify",
		}
	} else if config.CaptchaProvider == "recaptcha" {
		bc.captchaConfig = CaptchaConfig{
			js:       "https://www.google.com/recaptcha/api.js",
			key:      "g-recaptcha",
			validate: "https://www.google.com/recaptcha/api/siteverify",
		}
	} else if config.CaptchaProvider == "turnstile" {
		bc.captchaConfig = CaptchaConfig{
			js:       "https://challenges.cloudflare.com/turnstile/v0/api.js",
			key:      "cf-turnstile",
			validate: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		}
	} else {
		return nil, fmt.Errorf("invalid captcha provider: %s", config.CaptchaProvider)
	}

	return &bc, nil
}

func (bc *CaptchaProtect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP, ipRange := bc.getClientIP(req)
	if req.URL.Path == bc.config.ChallengeURL {
		if req.Method == http.MethodGet {
			bc.serveChallengePage(rw)
		} else if req.Method == http.MethodPost {
			bc.verifyChallengePage(rw, req, clientIP)
		} else {
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	} else if req.URL.Path == "/captcha-protect/stats" && bc.config.EnableStatsPage == "true" {
		bc.serveStatsPage(rw, clientIP)
		return
	}

	if !bc.shouldApply(req, clientIP) {
		bc.next.ServeHTTP(rw, req)
		return
	}
	bc.registerRequest(ipRange)

	if bc.trippedRateLimit(ipRange) {
		http.Redirect(rw, req, bc.config.ChallengeURL, http.StatusFound)
	} else {
		bc.next.ServeHTTP(rw, req)
	}
}

func (bc *CaptchaProtect) serveChallengePage(rw http.ResponseWriter) {
	tmpl, err := template.ParseFiles(bc.config.ChallengeTmpl)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error parsing template: %v", err), http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(rw, map[string]string{
		"SiteKey":      bc.config.SiteKey,
		"FrontendJS":   bc.captchaConfig.js,
		"FrontendKey":  bc.captchaConfig.key,
		"ChallengeURL": bc.config.ChallengeURL,
	})
	if err != nil {
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (bc *CaptchaProtect) serveStatsPage(rw http.ResponseWriter, ip string) {
	if ip != "127.0.0.1" {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	fmt.Fprint(rw, "Hits\tRange\n")
	for k, v := range bc.rateCache.Items() {
		fmt.Fprintf(rw, "%d\t%s\n", v.Object.(uint), k)
	}

	rw.WriteHeader(http.StatusOK)
}

func (bc *CaptchaProtect) verifyChallengePage(rw http.ResponseWriter, req *http.Request, ip string) {
	response := req.FormValue(bc.captchaConfig.key + "-response")
	if response == "" {
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return
	}

	var body = url.Values{}
	body.Add("secret", bc.config.SecretKey)
	body.Add("response", response)
	resp, err := http.PostForm(bc.captchaConfig.validate, body)
	if err != nil {
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var captchaResponse captchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}
	if captchaResponse.Success {
		bc.verifiedCache.Set(ip, true, lru.DefaultExpiration)
		http.Redirect(rw, req, "/", http.StatusFound)
		return
	}

	http.Error(rw, "Validation failed", http.StatusForbidden)
}

func (bc *CaptchaProtect) shouldApply(req *http.Request, clientIP string) bool {
	_, verified := bc.verifiedCache.Get(clientIP)
	if verified {
		return false
	}

	if IsIpExcluded(clientIP, bc.exemptIps) {
		return false
	}

	if bc.isGoodBot(req, clientIP) {
		return false
	}

	for _, route := range bc.config.ProtectRoutes {
		if strings.HasPrefix(req.URL.Path, route) {
			return true
		}
	}

	return false
}

func IsIpExcluded(clientIP string, exemptIps []*net.IPNet) bool {
	ip := net.ParseIP(clientIP)
	for _, block := range exemptIps {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

func (bc *CaptchaProtect) trippedRateLimit(ip string) bool {
	v, ok := bc.rateCache.Get(ip)
	if !ok {
		// todo: better logging
		os.Stderr.WriteString(fmt.Sprintf("IP not found: %s\n", ip))
		return false
	}
	return v.(uint) > bc.config.RateLimit
}

func (bc *CaptchaProtect) registerRequest(ip string) {
	err := bc.rateCache.Add(ip, uint(1), lru.DefaultExpiration)
	if err == nil {
		return
	}

	_, err = bc.rateCache.IncrementUint(ip, uint(1))
	if err != nil {
		log.Errorf("Unable to set rate cache for %s", ip)
	}
}

func (bc *CaptchaProtect) getClientIP(req *http.Request) (string, string) {
	ip := req.Header.Get(bc.config.IPForwardedHeader)
	if bc.config.IPForwardedHeader != "" && ip != "" {
		components := strings.Split(ip, ",")
		ip = strings.TrimSpace(components[0])
	} else {
		ip = req.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		host, _, _ := net.SplitHostPort(ip)
		ip = host
	}

	return ParseIp(ip)
}

func ParseIp(ip string) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip, ip
	}

	if parsedIP.To4() != nil {
		ipParts := strings.Split(ip, ".")
		if len(ipParts) >= 2 {
			return ip, ipParts[0] + "." + ipParts[1]
		}
	}

	if parsedIP.To16() != nil {
		ipParts := strings.Split(ip, ":")
		if len(ipParts) >= 4 {
			return ip, strings.Join(ipParts[:4], ":")
		}
	}

	return ip, ip
}

func (bc *CaptchaProtect) isGoodBot(req *http.Request, clientIP string) bool {
	if bc.config.ProtectParameters == "true" {
		if len(req.URL.Query()) > 0 {
			return false
		}
	}

	bot, ok := bc.botCache.Get(clientIP)
	if ok {
		return bot.(bool)
	}

	v := IsIpGoodBot(clientIP, bc.config.GoodBots)
	bc.botCache.Set(clientIP, v, lru.DefaultExpiration)
	return v
}

func IsIpGoodBot(clientIP string, goodBots []string) bool {
	// lookup the hostname for a given IP
	hostname, err := net.LookupAddr(clientIP)
	if err != nil || len(hostname) == 0 {
		return false
	}

	// then nslookup that hostname to avoid spoofing
	resolvedIP, err := net.LookupIP(hostname[0])
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

func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}
