# Captcha Protect
[![lint-test](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml/badge.svg)](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/libops/captcha-protect)](https://goreportcard.com/report/github.com/libops/captcha-protect)

Traefik middleware to challenge individual IPs in a subnet when traffic spikes are detected from that subnet, using a captcha of your choice for the challenge (turnstile, recaptcha, or hcaptcha).

You may have seen CAPTCHAs added to individual forms on the web to prevent bots from spamming submissions. This plugin extends that concept to your entire site (or specific routes on your site), effectively placing your entire site behind a CAPTCHA. However, the CAPTCHA is only triggered when a spike in traffic is detected from the same IP subnet. Once the CAPTCHA is successfully completed, that IP is no longer challenged, allowing uninterrupted browsing.

## Config

### Example

Below is an example `docker-compose.yml` with traefik as the frontend, and nginx as the backend. nginx is using this middleware to protect the entire site (`protectRoutes: "/"`)

Since the config values aren't specified, captcha-protect would use the default `rateLimit: 20` and `window: 86400` so any IPv4 in `X.Y.0.0/16` (or ipv6 in `/64`) could only access the site 20 times before individual IPs in that subnet are required to pass a captcha to continue browsing.

```yaml
networks:
    default:
services:
    nginx:
        image: nginx:${NGINX_TAG}
        labels:
            traefik.enable: true
            traefik.http.routers.nginx.entrypoints: http
            traefik.http.routers.nginx.service: nginx
            traefik.http.routers.nginx.rule: Host(`${DOMAIN}`)
            traefik.http.services.nginx.loadbalancer.server.port: 80
            traefik.http.routers.nginx.middlewares: captcha-protect@docker
            traefik.http.middlewares.captcha-protect.plugin.captcha-protect.protectRoutes: "/"
            traefik.http.middlewares.captcha-protect.plugin.captcha-protect.captchaProvider: turnstile
            traefik.http.middlewares.captcha-protect.plugin.captcha-protect.siteKey: ${TURNSTILE_SITE_KEY}
            traefik.http.middlewares.captcha-protect.plugin.captcha-protect.secretKey: ${TURNSTILE_SECRET_KEY}
            traefik.http.middlewares.captcha-protect.plugin.captcha-protect.goodBots: apple.com,archive.org,duckduckgo.com,facebook.com,google.com,googlebot.com,googleusercontent.com,instagram.com,kagibot.org,linkedin.com,msn.com,openalex.org,twitter.com,x.com
        networks:
            default:
                aliases:
                  - nginx
    traefik:
        image: traefik:${TRAEFIK_TAG}
        command: >-
            --api.insecure=false
            --api.dashboard=false
            --api.debug=false
            --ping=true
            --entryPoints.http.address=:80
            --providers.docker=true
            --providers.docker.network=default
            --experimental.plugins.captcha-protect.modulename=github.com/libops/captcha-protect
            --experimental.plugins.captcha-protect.version=v1.0.0
        volumes:
            - /var/run/docker.sock:/var/run/docker.sock:z
        ports:
            - "80:80"
        networks:
            default:
                aliases:
                    - traefik
        healthcheck:
            test: traefik healthcheck --ping
        depends_on:
            nginx:
                condition: service_started
```
### Config options

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
| enableStatsPage     | string                | "false"                 | Allow `exemptIps` to access `/captcha-protect/stats` to see the status of the rate limiter                                                                           |
| logLevel            | string                | "INFO"                  | This middleware's log level. Possible values: ERROR, WARNING, INFO, or DEBUG                                                                                       |


### Good Bots

To avoid having this middleware impact your SEO score, it's recommended to provide a value for `goodBots`. By default, no bots will be allowed to crawl your protected routes beyond the rate limit unless their second level domain (e.g. `google.com`) is configured as a good bot.

A good default value for `goodBots` would be:

```
goodBots: apple.com,archive.org,duckduckgo.com,facebook.com,google.com,googlebot.com,googleusercontent.com,instagram.com,kagibot.org,linkedin.com,msn.com,openalex.org,twitter.com,x.com
```

**However** if you set the config parameter `protectParameters="true"`, even good bots won't be allowed to crawl protected routes if a URL parameter is on the request (e.g. `/foo?bar=baz`). This `protectParameters` feature is meant to help protect faceted search pages.

## Similar projects

- [Traefik RateLimit middleware](https://doc.traefik.io/traefik/middlewares/http/ratelimit/) - the core traefik ratelimit middleware will start sending 429 responses based on individual IPs, which might not be good enough to protect against traffic coming from distributed networks.
- [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin) has a captcha option, but requires integrating with crowdsec to verify individual IPs. This plugin (captcha-protect) instead just checks the traffic actually visiting your site and verifies the traffic is from a person only when the traffic exceeds some rate limit you configure.

## Attribution

- the original implementation of this logic was [a drupal module called turnstile_protect](https://www.drupal.org/project/turnstile_protect). This traefik plugin was made to make the challenge logic even more perfomant than that Drupal module, and also to provide this bot protection to non-Drupal websites
- making general captcha structs to support multiple providers was based on the work in [crowdsec-bouncer-traefik-plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
- in memory cache thanks to https://github.com/patrickmn/go-cache
