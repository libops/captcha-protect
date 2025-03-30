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
	"regexp"
	"slices"
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
	IPDepth               int      `json:"ipDepth"`
	ProtectParameters     string   `json:"protectParameters"`
	ProtectRoutes         []string `json:"protectRoutes"`
	ExcludeRoutes         []string `json:"excludeRoutes"`
	ProtectFileExtensions []string `json:"protectFileExtensions"`
	ProtectHttpMethods    []string `json:"protectHttpMethods"`
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
	Mode                  string   `json:"mode"`
	protectRoutesRegex    []*regexp.Regexp
	excludeRoutesRegex    []*regexp.Regexp
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
	tmpl          *template.Template
	ipv4Mask      net.IPMask
	ipv6Mask      net.IPMask
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
		RateLimit:             20,
		Window:                86400,
		IPv4SubnetMask:        16,
		IPv6SubnetMask:        64,
		IPForwardedHeader:     "",
		ProtectParameters:     "false",
		ProtectRoutes:         []string{},
		ExcludeRoutes:         []string{},
		ProtectHttpMethods:    []string{},
		ProtectFileExtensions: []string{},
		GoodBots:              []string{},
		ExemptIPs:             []string{},
		ChallengeURL:          "/challenge",
		ChallengeTmpl:         "challenge.tmpl.html",
		EnableStatsPage:       "false",
		LogLevel:              "INFO",
		IPDepth:               0,
		CaptchaProvider:       "turnstile",
		Mode:                  "prefix",
		protectRoutesRegex:    []*regexp.Regexp{},
		excludeRoutesRegex:    []*regexp.Regexp{},
	}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return NewCaptchaProtect(ctx, next, config, name)
}

func NewCaptchaProtect(ctx context.Context, next http.Handler, config *Config, name string) (*CaptchaProtect, error) {
	var logLevel slog.LevelVar
	logLevel.Set(slog.LevelInfo)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})
	log = slog.New(handler)

	level, err := ParseLogLevel(config.LogLevel)
	if err != nil {
		log.Warn("Unknown log level", "err", err)
	}
	logLevel.Set(level)

	expiration := time.Duration(config.Window) * time.Second
	log.Debug("Captcha config", "config", config)

	if len(config.ProtectRoutes) == 0 && config.Mode != "suffix" {
		return nil, fmt.Errorf("you must protect at least one route with the protectRoutes config value. / will cover your entire site")
	}

	if config.Mode == "regex" {
		for _, r := range config.ProtectRoutes {
			cr, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in protectRoutes: %s", r)
			}
			config.protectRoutesRegex = append(config.protectRoutesRegex, cr)
		}
		for _, r := range config.ExcludeRoutes {
			cr, err := regexp.Compile(r)
			if err != nil {
				return nil, fmt.Errorf("invalid regex in excludeRoutes: %s", r)
			}
			config.excludeRoutesRegex = append(config.excludeRoutesRegex, cr)
		}
	} else if config.Mode != "prefix" && config.Mode != "suffix" {
		return nil, fmt.Errorf("unknown mode: %s. Supported values are prefix, suffix, and regex.", config.Mode)
	}

	if config.ChallengeURL == "/" {
		return nil, fmt.Errorf("your challenge URL can not be the entire site. Default is `/challenge`. A blank value will have challenges presented on the visit that trips the rate limit")
	}

	if len(config.ProtectHttpMethods) == 0 {
		config.ProtectHttpMethods = []string{
			"GET",
			"HEAD",
		}
	}
	config.ParseHttpMethods()

	var tmpl *template.Template
	if _, err := os.Stat(config.ChallengeTmpl); os.IsNotExist(err) {
		log.Warn("Unable to find template file. Using default template.", "challengeTmpl", config.ChallengeTmpl)
		ts := getDefaultTmpl()
		tmpl, err = template.New("challenge").Parse(ts)
		if err != nil {
			return nil, fmt.Errorf("unable to parse challenge template: %v", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("error checking for template file %s: %v", config.ChallengeTmpl, err)
	} else {
		tmpl, err = template.ParseFiles(config.ChallengeTmpl)
		if err != nil {
			return nil, fmt.Errorf("unable to parse challenge template file %s: %v", config.ChallengeTmpl, err)
		}
	}

	if !slices.Contains(config.ProtectFileExtensions, "html") {
		config.ProtectFileExtensions = append(config.ProtectFileExtensions, "html")
	}

	// transform exempt IP strings into what go can easily parse (net.IPNet)
	var ips []*net.IPNet
	exemptIps := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/8",
	}
	exemptIps = append(exemptIps, config.ExemptIPs...)
	for _, ip := range exemptIps {
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
		tmpl:          tmpl,
	}

	err = bc.SetIpv4Mask(config.IPv4SubnetMask)
	if err != nil {
		return nil, err
	}

	err = bc.SetIpv6Mask(config.IPv6SubnetMask)
	if err != nil {
		return nil, err
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
	challengeOnPage := bc.ChallengeOnPage()
	if challengeOnPage && req.Method == http.MethodPost {
		response := req.FormValue(bc.captchaConfig.key + "-response")
		if response == "" {
			if !slices.Contains(bc.config.ProtectHttpMethods, req.Method) {
				bc.next.ServeHTTP(rw, req)
				return
			}
		} else {
			statusCode := bc.verifyChallengePage(rw, req, clientIP)
			log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "status", statusCode, "useragent", req.UserAgent())
			return
		}
	}

	if req.URL.Path == bc.config.ChallengeURL {
		if req.Method == http.MethodGet {
			destination := req.URL.Query().Get("destination")
			log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "destination", destination, "useragent", req.UserAgent())
			bc.serveChallengePage(rw, destination)
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

	if !bc.trippedRateLimit(ipRange) {
		bc.next.ServeHTTP(rw, req)
		return
	}

	if bc.ChallengeOnPage() {
		log.Info("Captcha challenge", "clientIP", clientIP, "method", req.Method, "path", req.URL.Path, "useragent", req.UserAgent())
		bc.serveChallengePage(rw, req.URL.Path)
		return
	}
	encodedURI := url.QueryEscape(req.RequestURI)
	url := fmt.Sprintf("%s?destination=%s", bc.config.ChallengeURL, encodedURI)
	http.Redirect(rw, req, url, http.StatusFound)
}

func (bc *CaptchaProtect) serveChallengePage(rw http.ResponseWriter, destination string) {
	d := map[string]string{
		"SiteKey":      bc.config.SiteKey,
		"FrontendJS":   bc.captchaConfig.js,
		"FrontendKey":  bc.captchaConfig.key,
		"ChallengeURL": bc.config.ChallengeURL,
		"Destination":  destination,
	}
	status := http.StatusOK
	if bc.ChallengeOnPage() {
		status = http.StatusTooManyRequests
	}
	rw.WriteHeader(status)

	err := bc.tmpl.Execute(rw, d)
	if err != nil {
		log.Error("Unable to execute go template", "tmpl", bc.config.ChallengeTmpl, "err", err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
	}
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
	if !slices.Contains(bc.config.ProtectHttpMethods, req.Method) {
		return false
	}

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

	if bc.config.Mode == "regex" {
		return bc.RouteIsProtectedRegex(req.URL.Path)
	}

	if bc.config.Mode == "suffix" {
		return bc.RouteIsProtectedSuffix(req.URL.Path)
	}

	return bc.RouteIsProtectedPrefix(req.URL.Path)
}

func (bc *CaptchaProtect) RouteIsProtectedPrefix(path string) bool {
protected:
	for _, route := range bc.config.ProtectRoutes {
		if !strings.HasPrefix(path, route) {
			continue
		}

		// we're on a protected route - make sure this route doesn't have an exclusion
		for _, eRoute := range bc.config.ExcludeRoutes {
			if strings.HasPrefix(path, eRoute) {
				continue protected
			}
		}

		// if this path isn't a file, go ahead and mark this path as protected
		ext := filepath.Ext(path)
		ext = strings.TrimPrefix(ext, ".")
		if ext == "" {
			return true
		}

		// if we have a file extension, see if we should protect this file extension type
		for _, protectedExtensions := range bc.config.ProtectFileExtensions {
			if strings.EqualFold(ext, protectedExtensions) {
				return true
			}
		}
	}

	return false
}

func (bc *CaptchaProtect) RouteIsProtectedSuffix(path string) bool {
protected:
	for _, route := range bc.config.ProtectRoutes {
		cleanPath := path
		ext := filepath.Ext(path)
		if ext != "" {
			cleanPath = strings.TrimSuffix(path, ext)
		}
		if !strings.HasSuffix(cleanPath, route) {
			continue
		}

		// we're on a protected route - make sure this route doesn't have an exclusion
		for _, eRoute := range bc.config.ExcludeRoutes {
			if strings.HasPrefix(cleanPath, eRoute) {
				continue protected
			}
		}

		// if this path isn't a file, go ahead and mark this path as protected
		ext = strings.TrimPrefix(ext, ".")
		if ext == "" {
			return true
		}

		// if we have a file extension, see if we should protect this file extension type
		for _, protectedExtensions := range bc.config.ProtectFileExtensions {
			if strings.EqualFold(ext, protectedExtensions) {
				return true
			}
		}
	}

	return false
}

func (bc *CaptchaProtect) RouteIsProtectedRegex(path string) bool {
protected:
	for _, routeRegex := range bc.config.protectRoutesRegex {
		matched := routeRegex.MatchString(path)
		if !matched {
			continue
		}

		for _, excludeRegex := range bc.config.excludeRoutesRegex {
			excluded := excludeRegex.MatchString(path)
			if excluded {
				continue protected
			}
		}

		ext := filepath.Ext(path)
		ext = strings.TrimPrefix(ext, ".")
		if ext == "" {
			return true
		}

		for _, protectedExtension := range bc.config.ProtectFileExtensions {
			if strings.EqualFold(ext, protectedExtension) {
				return true
			}
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
		depth := bc.config.IPDepth
		ip = ""
		for i := len(components) - 1; i >= 0; i-- {
			_ip := strings.TrimSpace(components[i])
			if IsIpExcluded(_ip, bc.exemptIps) {
				continue
			}
			if depth == 0 {
				ip = _ip
				break
			}
			depth--
		}
		if ip == "" {
			log.Debug("No non-exempt IPs in header. req.RemoteAddr", "ipDepth", bc.config.IPDepth, bc.config.IPForwardedHeader, req.Header.Get(bc.config.IPForwardedHeader))
			ip = req.RemoteAddr
		}
	} else {
		if bc.config.IPForwardedHeader != "" {
			log.Debug("Received a blank header value. Defaulting to real IP")
		}
		ip = req.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		host, _, _ := net.SplitHostPort(ip)
		ip = host
	}

	return bc.ParseIp(ip)
}

func (bc *CaptchaProtect) ParseIp(ip string) (string, string) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ip, ip
	}

	// For IPv4 addresses
	if parsedIP.To4() != nil {
		subnet := parsedIP.Mask(bc.ipv4Mask)
		return ip, subnet.String()
	}

	// For IPv6 addresses
	if parsedIP.To16() != nil {
		subnet := parsedIP.Mask(bc.ipv6Mask)
		return ip, subnet.String()
	}

	log.Warn("Unknown ip version", "ip", ip)

	return ip, ip
}

func (bc *CaptchaProtect) SetIpv4Mask(m int) error {
	if m < 8 || m > 32 {
		return fmt.Errorf("invalid ipv4 mask: %d. Must be between 8 and 32", m)
	}
	bc.ipv4Mask = net.CIDRMask(m, 32)

	return nil
}

func (bc *CaptchaProtect) SetIpv6Mask(m int) error {
	if m < 8 || m > 128 {
		return fmt.Errorf("invalid ipv6 mask: %d. Must be between 8 and 128", m)
	}
	bc.ipv6Mask = net.CIDRMask(m, 128)

	return nil
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

func (bc *CaptchaProtect) SetExemptIps(exemptIps []*net.IPNet) {
	bc.exemptIps = exemptIps
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

// log a warning if protected methods contains an invalid method
func (c *Config) ParseHttpMethods() {
	for _, method := range c.ProtectHttpMethods {
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE":
			continue
		default:
			log.Warn("unknown http method", "method", method)
		}
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

func getDefaultTmpl() string {
	return `<html>
  <head>
    <title>Verifying connection</title>
    <script src="{{ .FrontendJS }}" async defer referrerpolicy="no-referrer"></script>
  </head>
  <body>
    <h1>Verifying connection</h1>
    <p>One moment while we verify your network connection.</p>
    <form action="{{ .ChallengeURL }}" method="post" id="captcha-form" accept-charset="UTF-8">
        <div
            data-callback="captchaCallback"
            class="{{ .FrontendKey }}"
            data-sitekey="{{ .SiteKey }}"
            data-theme="auto"
            data-size="normal"
            data-language="auto"
            data-retry="auto"
            interval="8000"
            data-appearance="always">
        </div>
        <input type="hidden" name="destination" value="{{ .Destination }}">
    </form>
    <script type="text/javascript">
        function captchaCallback(token) {
            setTimeout(function() {
                document.getElementById("captcha-form").submit();
            }, 1000);
        }
    </script>
  </body>
</html>`
}

func (bc *CaptchaProtect) ChallengeOnPage() bool {
	return bc.config.ChallengeURL == ""
}
