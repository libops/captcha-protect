# Captcha Protect

Traefik middleware to challenge individual IPs in a subnet when traffic spikes are detected from that subnet, using a captcha of your choice for the challenge

You may have seen captchas added to individual forms on the web to protect from bots spamming submissions on the form. This plugin takes that concept and applies it to your entire site; basically putting your entire site behind a captcha. However, the captcha is only presented when a spike in traffic is seen from the same IP subnet the request is coming from. Once the captcha is passed, the individual IP is no longer challenged and is free to continue browing unchallenged.

## Config

| JSON Key            | Type                  | Default Value           | Description                                                                                                                                                        |
|---------------------|-----------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| protectRoutes       | []string (required)   | ""                      | Comma separated list of route prefixes to protect with this middleware. e.g. "/" protects the whole site. "/browse" protects any URL that starts with that string. |
| captchaProvider     | string (required)     | ""                      | The captcha type to use. Supported values are turnstile, hcaptcha, and recaptcha.                                                                                  |
| siteKey             | string (required)     | ""                      | The captcha site key                                                                                                                                               |
| secretKey           | string (required)     | ""                      | The captcha secret key                                                                                                                                             |
| rateLimit           | uint                  | 20                      | How many requests are allowed from a subnet before individuals are challenged                                                                                      |
| window              | int                   | 86400                   | How long requests for a given subnet are monitored (in seconds)                                                                                                    |
| ipv4subnetMask      | int                   | 16                      | The CIDR subnet mask to group IPv4 requests into for the rate limiter                                                                                              |
| ipv6subnetMask      | int                   | 64                      | The CIDR subnet mask to group IPv6 requests into for the rate limiter                                                                                              |
| ipForwardedHeader   | string                | ""                      | If traefik is behind a load balancer, where to look for the original client address                                                                                |
| goodBots            | []string (encouraged) | see below               | Comma separated list of second level domain names for bots that are never challened/rate limited. See below                                                        |
| protectParameters   | string                | "false"                 | Do not allow even good bots to pass the rate limiter if the request has URL parameters. Meant to help protect faceted search pages.                                |
| exemptIps           | []string              | privateIPs              | IP address(es) in CIDR format that should never be challenged. Private IP ranges are always included                                                               |
| challengeURL        | string                | "/challenge"            | The URL on the site to send challenges to. Will override any URL at that route                                                                                     |
| challengeTmpl       | string                | "./challenge.tmpl.html" | HTML go template file to serve the captcha challenge.                                                                                                              |
| enableStatsPage     | string                | "false"                 | Allow exemptIps to access `/captcha-protect/stats` to see the status of the rate limiter                                                                           |
| logLevel            | string                | "INFO"                  | This middleware's log level. Possible values: ERROR, WARNING, INFO, or DEBUG                                                                                       |


### Good Bots

To avoid having this middleware impact your SEO score, it's recommended to provide a value for `goodBots`. By default, no bots will be allowed to crawl your protected routes unless their second level domain (e.g. `google.com`) is configured as a good bot.

A good default value for `goodBots` would be:

```
goodBots: apple.com,archive.org,duckduckgo.com,facebook.com,google.com,googlebot.com,googleusercontent.com,instagram.com,kagibot.org,linkedin.com,msn.com,openalex.org,twitter.com,x.com
```

**However** if you set the config parameter `protectParameters="true"`, even good bots won't be allowed to crawl protected routes if a URL parameter is on the request (e.g. `/foo?bar=baz`). This feature is meant to help protect faceted search pages.

## Similar projects

- [Traefik RateLimit middleware](https://doc.traefik.io/traefik/middlewares/http/ratelimit/) - this middleware will start sending 429 responses based on individual IPs, which might not be good enough to protect against traffic coming from more widespread ip ranges.
- [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) has a captcha option, but requires integrating with crowdsec. This plugin instead just checks the traffic based coming to your site from any IP range and verifies they're human with a captcha challenge.

## Attribution

- the original implementation of this logic was [a drupal module called turnstile_protect](https://www.drupal.org/project/turnstile_protect). This traefik plugin was made to make the challenge logic even more perfomant than that module
- making general captcha structs to support multiple providers was based on the work in [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
