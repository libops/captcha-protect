// Traefik's plugin service cannot resolve major-version module suffixes for
// plugins with vendored dependencies. Keep this module on the v1 path.
module github.com/libops/captcha-protect

go 1.25.0

require github.com/patrickmn/go-cache v2.1.0+incompatible
