package captcha_protect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"
	"text/template"
	"time"

	log "github.com/discoverygarden/traefik-ultimate-bad-bot-blocker/utils"

	lru "github.com/patrickmn/go-cache"
)

var (
	lookupAddrFunc = net.LookupAddr
	lookupIPFunc   = net.LookupIP
)

type Config struct {
	RateLimit         uint     `json:"rateLimit"`
	Window            int64    `json:"window"`
	IPv4SubnetMask    int      `json:"ipv4subnetMask"`
	IPv6SubnetMask    int      `json:"ipv6subnetMask"`
	IPForwardedHeader string   `json:"ipForwardedHeader"`
	ProtectParameters string   `json:"protectParameters"`
	ProtectRoutes     []string `json:"protectRoutes"`
	GoodBots          []string `json:"goodBots"`
	ExemptIPs         []string `json:"exemptIps"`
	ChallengeURL      string   `json:"challengeURL"`
	ChallengeTmpl     string   `json:"challengeTmpl"`
	CaptchaProvider   string   `json:"captchaProvider"`
	SiteKey           string   `json:"siteKey"`
	SecretKey         string   `json:"secretKey"`
	EnableStatsPage   string   `json:"enableStatsPage"`
	LogLevel          string   `json:"loglevel,omitempty"`
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

type statsResponse struct {
	Rate     map[string]uint    `json:"rate"`
	Bots     map[string]bool    `json:"bots"`
	Verified map[string]bool    `json:"verified"`
	Memory   map[string]uintptr `json:"memory"`
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
		GoodBots:          []string{},
		ExemptIPs: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/8",
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

	expiration := time.Duration(config.Window) * time.Second
	log.Debugf("config: %+v", config)

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
		next:      next,
		name:      name,
		config:    config,
		rateCache: lru.New(expiration, 1*time.Minute),
		botCache:  lru.New(expiration, 1*time.Minute),
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
			log.Infof("%s %s %s %s", clientIP, req.Method, req.URL.Path, req.UserAgent())
			bc.serveChallengePage(rw, req)
		} else if req.Method == http.MethodPost {
			statusCode := bc.verifyChallengePage(rw, req, clientIP)
			log.Infof("%s %s %s %d %s", clientIP, req.Method, req.URL.Path, statusCode, req.UserAgent())
		} else {
			http.Error(rw, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	} else if req.URL.Path == "/captcha-protect/stats" && bc.config.EnableStatsPage == "true" {
		log.Infof("%s %s %s %s", clientIP, req.Method, req.URL.Path, req.UserAgent())
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
		log.Errorf("Unable to parse go template %s: %v", bc.config.ChallengeTmpl, err)
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
		log.Errorf("Unable to execute go template %s: %v %v", bc.config.ChallengeTmpl, d, err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusOK)
}

func (bc *CaptchaProtect) serveStatsPage(rw http.ResponseWriter, ip string) {
	// only allow excluded IPs from viewing
	if !IsIpExcluded(ip, bc.exemptIps) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	resp := statsResponse{
		Memory: make(map[string]uintptr, 3),
	}

	items := bc.rateCache.Items()
	resp.Rate = make(map[string]uint, len(items))
	resp.Memory["rate"] = reflect.TypeOf(resp.Rate).Size()
	for k, v := range items {
		resp.Rate[k] = v.Object.(uint)
		resp.Memory["rate"] += reflect.TypeOf(k).Size()
		resp.Memory["rate"] += reflect.TypeOf(v).Size()
		resp.Memory["rate"] += uintptr(len(k))
	}

	items = bc.botCache.Items()
	resp.Bots = make(map[string]bool, len(items))
	resp.Memory["bot"] = reflect.TypeOf(resp.Bots).Size()
	for k, v := range items {
		resp.Bots[k] = v.Object.(bool)
		resp.Memory["bot"] += reflect.TypeOf(k).Size()
		resp.Memory["bot"] += reflect.TypeOf(v).Size()
		resp.Memory["bot"] += uintptr(len(k))
	}

	items = bc.verifiedCache.Items()
	resp.Verified = make(map[string]bool, len(items))
	resp.Memory["verified"] = reflect.TypeOf(resp.Verified).Size()
	for k, v := range items {
		resp.Verified[k] = v.Object.(bool)
		resp.Memory["verified"] += reflect.TypeOf(k).Size()
		resp.Memory["verified"] += reflect.TypeOf(v).Size()
		resp.Memory["verified"] += uintptr(len(k))
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		log.Errorf("failed to marshal JSON: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rw.WriteHeader(http.StatusOK)
	rw.Header().Set("Content-Type", "application/json")
	_, err = rw.Write(jsonData)
	if err != nil {
		log.Errorf("failed to write JSON on stats request: %v", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
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
		log.Errorf("Unable to validate captcha %s: %v %v", bc.captchaConfig.validate, body, err)
		http.Error(rw, "Internal error", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}
	defer resp.Body.Close()

	var captchaResponse captchaResponse
	err = json.NewDecoder(resp.Body).Decode(&captchaResponse)
	if err != nil {
		log.Errorf("Unable to unmarshal captcha response %s: %v", bc.captchaConfig.validate, err)
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
			log.Errorf("Unable to unescape destination: %s: %v", destination, err)
			u = "/"
		}
		http.Redirect(rw, req, u, http.StatusFound)
		return http.StatusFound
	}

	http.Error(rw, "Validation failed", http.StatusForbidden)

	return http.StatusForbidden
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
		log.Errorf("IP not found, but should already be set: %s\n", ip)
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
