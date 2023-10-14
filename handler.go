package caddy_ja3

import (
	"errors"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var fingerprints = map[string]string{
	"09e8da600773390473b708b18c586b6b": "IOS", "1c6a21040d734c88908c9f569db6e84e": "Android", "44f7ed5185d22c92b96da72dbe68d307": "Safari", "47e81c30acfb7136fd63c8c90db110f2": "IOS", "4ae9619a31749ee24c7e77ec3162be41": "IOS", "4e3f1cb6f800f5f840099be45843aa0e": "Android", "664f25de9096f23cf8dae21a69a3ec6c": "Android", "aa56c057ad164ec4fdcb7a5a283be9fc": "Chrome", "b1efda11c805621e0f9cdc311958cb8c": "Firefox", "b6c462146270c94ed8e339bcf4fff25f": "Android", "ba3f95f76ace81b9429d294856c194b5": "Firefox", "e65e53f6d9a7a0df7e97cf1bd5ba6082": "Android", "26615da679e653f4882c85942232900e": "Git",
}

func init() {
	caddy.RegisterModule(JA3Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja3", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		handler := &JA3Handler{}
		return handler, handler.UnmarshalCaddyfile(h.Dispenser)
	})
}

type JA3Handler struct {
	cache *Cache
	log   *zap.Logger
}

func (JA3Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja3",
		New: func() caddy.Module { return new(JA3Handler) },
	}
}

// Provision implements caddy.Provisioner
func (h *JA3Handler) Provision(ctx caddy.Context) error {
	a, err := ctx.App(CacheAppId)
	if err != nil {
		return err
	}

	h.cache = a.(*Cache)
	h.log = ctx.Logger(h)
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (h *JA3Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Look for a boolean directive with the name "sort_ja3"
		if d.NextArg() {
			switch d.Val() {
			case "block_bots":
				if !d.NextArg() {
					return d.ArgErr()
				}
				switch d.Val() {
				case "true":
					BlockBots = true
				case "false":
					BlockBots = false
				default:
					return d.Errf("invalid value for block_bots: %s", d.Val())
				}

			default:
				return d.Errf("invalid directive: %s", d.Val())
			}
		}
	}
	return nil

}

// ServeHTTP implements caddyhttp.MiddlewareHandler
func (h *JA3Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	if req.TLS.HandshakeComplete {
		ja3 := h.cache.GetJA3(req.RemoteAddr)

		if ja3 == nil {
			h.log.Debug("ClientHello missing from cache for " + req.RemoteAddr)
		} else {
			if BlockBots {
				var browser string
				var ok bool
				if browser, ok = fingerprints[*ja3]; !ok {
					rw.WriteHeader(403)
					return errors.New("failed fingerprint test: "+ *ja3)
				}
				req.Header.Add("browser", browser)
			}
			h.log.Debug("Attaching JA3 to request for " + req.RemoteAddr)
			req.Header.Add("ja3", *ja3)
		}
	}

	return next.ServeHTTP(rw, req)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*JA3Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*JA3Handler)(nil)
	_ caddyfile.Unmarshaler       = (*JA3Handler)(nil)
)
