package captcha_protect

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/libops/captcha-protect/internal/state"
	lru "github.com/patrickmn/go-cache"
)

var (
	lookupAddrFunc = net.LookupAddr
	lookupIPFunc   = net.LookupIP
	log            *slog.Logger
)

type Config struct {
	RateLimit             uint     `json:"rateLimit"`
	Window                int64    `json:"window"`
	IPv4SubnetMask        int      `json:"ipv4subnetMask"`
	IPv6SubnetMask        int      `json:"ipv6subnetMask"`
	IPForwardedHeader     string   `json:"ipForwardedHeader"`
	ProtectParameters     string   `json:"protectParameters"`
	ProtectRoutes         []string `json:"protectRoutes"`
	ProtectFileExtensions []string `json:"protectFileExtensions"`
	GoodBots              []string `json:"goodBots"`
	ExemptIPs             []string `json:"exemptIps"`
	ChallengeURL          string   `json:"challengeURL"`
	ChallengeTmpl         string   `json:"challengeTmpl"`
	CaptchaProvider       string   `json:"captchaProvider"`
	SiteKey               string   `json:"siteKey"`
	SecretKey             string   `json:"secretKey"`
	EnableStatsPage       string   `json:"enableStatsPage"`
	LogLevel              string   `json:"loglevel,omitempty"`
	PersistentStateFile   string   `json:"persistentStateFile"`
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
		Window:            86400,
		IPv4SubnetMask:    16,
		IPv6SubnetMask:    64,
		IPForwardedHeader: "",
		ProtectParameters: "false",
		ProtectRoutes:     []string{},
		ProtectFileExtensions: []string{
			"html",
			"json",
		},
		GoodBots: []string{},
		ExemptIPs: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/8",
		},
		ChallengeURL:    "/challenge",
		ChallengeTmpl:   "challenge.tmpl.html",
		EnableStatsPage: "false",
		LogLevel:        "INFO",
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	var logLevel slog.LevelVar
	logLevel.Set(slog.LevelInfo)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})
	log = slog.New(handler)

	level, err := ParseLogLevel(config.LogLevel)
	if err != nil {
		log.Error("Unknown log level", "err", err)
	}
	logLevel.Set(level)

	expiration := time.Duration(config.Window) * time.Second
	log.Debug("Captcha config", "config", config)

	if len(config.ProtectRoutes) == 0 {
		return nil, fmt.Errorf("you must protect at least one route with the protectRoutes config value. / will cover your entire site")
	}

	if _, err := os.Stat(config.ChallengeTmpl); os.IsNotExist(err) {
		return nil, fmt.Errorf("template file does not exist: %s", config.ChallengeTmpl)
	} else if err != nil {
		return nil, fmt.Errorf("error check for template file %s: %v", config.ChallengeTmpl, err)
	}

	// transform exempt IP strings into what go can easily parse (net.IPNet)
	var ips []*net.IPNet
	for _, ip := range config.ExemptIPs {
		parsedIp, err := ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", ip, err)
		}
		ips = append(ips, parsedIp)
	}

	bc := CaptchaProtect{
		next:          next,
		name:          name,
		config:        config,
		rateCache:     lru.New(expiration, 1*time.Minute),
		botCache:      lru.New(expiration, 1*time.Hour),
		verifiedCache: lru.New(expiration, 1*time.Hour),
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

	if config.PersistentStateFile != "" {
		bc.loadState()
		childCtx, cancel := context.WithCancel(ctx)
		go bc.saveState(childCtx)
		go func() {
			<-ctx.Done()
			log.Debug("Context canceled, calling child cancel...")
			cancel()
		}()
	}

	return &bc, nil
}

func (bc *CaptchaProtect) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	clientIP, ipRange := bc.getClientIP(req)
	if req.URL.Path == bc.config.ChallengeURL {
		if req.Method == http.MethodGet {
			log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
			bc.serveChallengePage(rw, req)
		} else if req.Method == http.MethodPost {
			statusCode := bc.verifyChallengePage(rw, req, clientIP)
			log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "status", statusCode, "useragent", req.UserAgent())
		} else {
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	} else if req.URL.Path == "/captcha-protect/stats" && bc.config.EnableStatsPage == "true" {
		log.Info("Captcha stats", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
		bc.serveStatsPage(rw, clientIP)
		return
	}

	if !bc.shouldApply(req, clientIP) {
		bc.next.ServeHTTP(rw, req)
		return
	}
	bc.registerRequest(ipRange)

	if bc.trippedRateLimit(ipRange) {
		encodedURI := url.QueryEscape(req.RequestURI)
		url := fmt.Sprintf("%s?destination=%s", bc.config.ChallengeURL, encodedURI)
		http.Redirect(rw, req, url, http.StatusFound)
	} else {
		bc.next.ServeHTTP(rw, req)
	}
}

func (bc *CaptchaProtect) serveChallengePage(rw http.ResponseWriter, req *http.Request) {
	tmpl, err := template.ParseFiles(bc.config.ChallengeTmpl)
	if err != nil {
		log.Error("Unable to parse go template", "tmpl", bc.config.ChallengeTmpl, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}

	d := map[string]string{
		"SiteKey":      bc.config.SiteKey,
		"FrontendJS":   bc.captchaConfig.js,
		"FrontendKey":  bc.captchaConfig.key,
		"ChallengeURL": bc.config.ChallengeURL,
		"Destination":  req.URL.Query().Get("destination"),
	}
	err = tmpl.Execute(rw, d)
	if err != nil {
		log.Error("Unable to execute go template", "tmpl", bc.config.ChallengeTmpl, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (bc *CaptchaProtect) verifyChallengePage(rw http.ResponseWriter, req *http.Request, ip string) int {
	response := req.FormValue(bc.captchaConfig.key + "-response")
	if response == "" {
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return http.StatusBadRequest
	}

	var body = url.Values{}
	body.Add("secret", bc.config.SecretKey)
	body.Add("response", response)
	resp, err := http.PostForm(bc.captchaConfig.validate, body)
	if err != nil {
		log.Error("Unable to validate captcha", "url", bc.captchaConfig.validate, "body", body, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	defer resp.Body.Close()

	var captchaResponse captchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		log.Error("Unable to unmarshal captcha response", "url", bc.captchaConfig.validate, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	if captchaResponse.Success {
		bc.verifiedCache.Set(ip, true, lru.DefaultExpiration)
		destination := req.FormValue("destination")
		if destination == "" {
			destination = "%2F"
		}
		u, err := url.QueryUnescape(destination)
		if err != nil {
			log.Error("Unable to unescape destination", "destination", destination, "err", err)
			u = "/"
		}
		http.Redirect(rw, req, u, http.StatusFound)
		return http.StatusFound
	}

	http.Error(rw, "Validation failed", http.StatusForbidden)

	return http.StatusForbidden
}

func (bc *CaptchaProtect) serveStatsPage(rw http.ResponseWriter, ip string) {
	// only allow excluded IPs from viewing
	if !IsIpExcluded(ip, bc.exemptIps) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	state := state.GetState(bc.rateCache.Items(), bc.botCache.Items(), bc.verifiedCache.Items())
	jsonData, err := json.Marshal(state)
	if err != nil {
		log.Error("failed to marshal JSON", "err", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/json")
	_, err = rw.Write(jsonData)
	if err != nil {
		log.Error("failed to write JSON on stats reques", "err", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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

	return bc.RouteIsProtected(req.URL.Path)
}

func (bc *CaptchaProtect) RouteIsProtected(path string) bool {
	for _, route := range bc.config.ProtectRoutes {
		if strings.HasPrefix(path, route) {
			ext := filepath.Ext(path)
			ext = strings.TrimPrefix(ext, ".")
			if ext == "" {
				return true
			}

			skip := true
			for _, protectedExtensions := range bc.config.ProtectFileExtensions {
				if strings.EqualFold(ext, protectedExtensions) {
					skip = false
				}
			}
			if skip {
				continue
			}

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
		log.Error("IP not found, but should already be set", "ip", ip)
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
		log.Error("Unable to set rate cache", "ip", ip)
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

	return ParseIp(ip, bc.config.IPv4SubnetMask, bc.config.IPv6SubnetMask)
}

func ParseIp(ip string, ipv4Mask, ipv6Mask int) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip, ip
	}

	// For IPv4 addresses
	if parsedIP.To4() != nil {
		ipParts := strings.Split(ip, ".")
		var required int
		switch ipv4Mask {
		case 8:
			required = 1
		case 16:
			required = 2
		case 24:
			required = 3
		default:
			// fallback to a default, for example /16
			required = 2
		}
		if len(ipParts) >= required {
			subnet := strings.Join(ipParts[:required], ".")
			return ip, subnet
		}
	}

	// For IPv6 addresses
	if parsedIP.To16() != nil {
		ipParts := strings.Split(ip, ":")
		// Calculate the number of hextets required.
		required := ipv6Mask / 16
		if len(ipParts) >= required {
			subnet := strings.Join(ipParts[:required], ":")
			return ip, subnet
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

func ParseCIDR(cidr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return ipNet, nil
}

// Map string to slog.Level
func ParseLogLevel(level string) (slog.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARNING", "WARN":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown logl level %s", level)
	}
}

func (bc *CaptchaProtect) saveState(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	file, err := os.OpenFile(bc.config.PersistentStateFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Error("Unable to save state. Could not open or create file", "stateFile", bc.config.PersistentStateFile, "err", err)
		return
	}
	// we made sure the file is writable, we can continue in our loop
	file.Close()

	for {
		select {
		case <-ticker.C:
			log.Debug("Saving state")
			state := state.GetState(bc.rateCache.Items(), bc.botCache.Items(), bc.verifiedCache.Items())
			jsonData, err := json.Marshal(state)
			if err != nil {
				log.Error("failed unmarshalling state data", "err", err)
				break
			}
			err = os.WriteFile(bc.config.PersistentStateFile, jsonData, 0644)
			if err != nil {
				log.Error("failed saving state data", "err", err)
			}

		case <-ctx.Done():
			log.Debug("Context cancelled, stopping saveState")
			return
		}
	}
}

func (bc *CaptchaProtect) loadState() {
	fileContent, err := os.ReadFile(bc.config.PersistentStateFile)
	if err != nil || len(fileContent) == 0 {
		log.Warn("Failed to load state file.", "err", err)
		return
	}

	var state state.State
	err = json.Unmarshal(fileContent, &state)
	if err != nil {
		log.Error("Failed to unmarshal state file", "err", err)
		return
	}

	for k, v := range state.Rate {
		bc.rateCache.Set(k, v, lru.DefaultExpiration)
	}

	for k, v := range state.Bots {
		bc.botCache.Set(k, v, lru.DefaultExpiration)
	}

	for k, v := range state.Verified {
		bc.verifiedCache.Set(k, v, lru.DefaultExpiration)
	}

	log.Info("Loaded previous state")
}
