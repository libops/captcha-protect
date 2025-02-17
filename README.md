# Captcha Protect

Traefik middleware to challenge individual IPs in a subnet when traffic spikes are detected from that subnet, using a captcha of your choice for the challenge

You may have seen captchas added to individual forms on the web to protect from bots spamming submissions on the form. This plugin takes that concept and applies it to your entire site; basically putting your entire site behind a captcha. However, the captcha is only presented when a spike in traffic is seen from the same IP subnet the request is coming from. Once the captcha is passed, the individual IP is no longer challenged and is free to continue browing unchallenged.

## Config

| JSON Key            | Type              | Default Value           | Description  |
|---------------------|-------------------|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| captchaProvider     | string (required) | ""                      | The captcha type to use. Supported values are turnstile, hcaptcha, and recaptcha.                                                                       |
| siteKey             | string (required) | ""                      | The captcha site key                                                                                                                                    |
| secretKey           | string (required) | ""                      | The captcha secret key                                                                                                                                  |
| rateLimit           | uint              | 20                      | How many requests are allowed from a subnet before individuals are challenged                                                                           |
| window              | time.Duration     | 1d                      | How long requests for a given subnet are monitored                                                                                                      |
| ipv4subnetMask      | int               | 16                      | The CIDR subnet mask to group IPv4 requests into for the rate limiter                                                                                   |
| ipv6subnetMask      | int               | 64                      | The CIDR subnet mask to group IPv6 requests into for the rate limiter                                                                                   |
| ipForwardedHeader   | string            | ""                      | If traefik is behind a load balancer, where to look for the original client address                                                                     |
| protectRoutes       | []string          | ["/"]                   | Routes that start with the string(s) in this list. e.g. "/" protects the whole site. "/browse" protects any URL that starts with that string.           |
| goodBots            | []string          | see below               | List of second level domain names for bots that are never challened/rate limited. This it to keep your SEO score stable when this plugin is enabled     |
| protectParameters   | string            | "false"                 | Do not allow even good bots to pass the rate limiter if the request has URL parameters. Meant to help protect faceted search pages.                     |
| exemptIps           | []string          | privateIPs              | IP address(es) that should never be challened                                                                                                           |
| challengeURL        | string            | "/challenge"            | The URL on the site to send challenges to. Will override any URL at that route                                                                          |
| challengeTmpl       | string            | "./challenge.tmpl.html" | HTML go template file to serve the captcha challenge.                                                                                                   |
| enableStatsPage     | string            | "false"                 | Allow 127.0.0.1 to access /captcha-protect/stats to see the status of the rate limiter                                                                  |


### Good Bots

The bots by default that are allowed to come through no matter their rate limit (unless `protectParameters="true"` and a URL has a GET parameter).

```
duckduckgo.com
kagibot.org
googleusercontent.com
google.com
googlebot.com
msn.com
openalex.org
archive.org
linkedin.com
facebook.com
instagram.com
twitter.com
x.com
apple.com
```

## Similar projects

- [Traefik RateLimit middleware](https://doc.traefik.io/traefik/middlewares/http/ratelimit/) - this middleware will start sending 429 responses based on individual IPs, which might not be good enough to protect against traffic coming from more widespread ip ranges.
- [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) has a captcha option, but requires integrating with crowdsec. This plugin instead just checks the traffic based coming to your site from any IP range and verifies they're human with a captcha challenge.

## Attribution

- the original implementation of this logic was [a drupal module called turnstile_protect](https://www.drupal.org/project/turnstile_protect). This traefik plugin was made to make the challenge logic even more perfomant than that module
- making general captcha structs to support multiple providers was based on the work in [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
