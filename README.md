# Captcha Protect

[![lint-test](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml/badge.svg)](https://github.com/libops/captcha-protect/actions/workflows/lint-test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/libops/captcha-protect)](https://goreportcard.com/report/github.com/libops/captcha-protect)
[![codecov](https://codecov.io/gh/libops/captcha-protect/branch/main/graph/badge.svg)](https://codecov.io/gh/libops/captcha-protect)

Captcha Protect is a Traefik middleware that challenges client IPs on protected routes. It can use Turnstile, reCAPTCHA, hCaptcha, or proof-of-javascript for the challenge.

It requires Traefik `v3.6` or above.

## Documentation

The user and operator documentation now lives at:

<https://captcha-protect.libops.io/>

Start there for:

- Docker Compose configuration examples.
- Full configuration option reference.
- Preferred multi-layer routing guidance for protecting multiple services.
- Challenge template customization.
- Good bot bypasses, monitoring, and troubleshooting.

## Source Links

- Documentation source: <https://github.com/libops/captcha-protect-docs>
- Default challenge template: [challenge.tmpl.html](./challenge.tmpl.html)
