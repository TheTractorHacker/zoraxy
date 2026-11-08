package forward

import (
	"errors"
	"time"
)

const (
	LogTitle = "Forward Auth"

	DatabaseTable = "auth_sso_forward"

	DatabaseKeyAddress                = "address"
	DatabaseKeyResponseHeaders        = "responseHeaders"
	DatabaseKeyResponseClientHeaders  = "responseClientHeaders"
	DatabaseKeyRequestHeaders         = "requestHeaders"
	DatabaseKeyRequestIncludedCookies = "requestIncludedCookies"
	DatabaseKeyRequestExcludedCookies = "requestExcludedCookies"
	DatabaseKeyRequestIncludeBody     = "requestIncludeBody"
	DatabaseKeyUseXOriginalHeaders    = "useXOriginalHeaders"
	DatabaseKeyIgnoredPaths           = "ignoredPaths"
	DatabaseKeyOutpostURL             = "outpostUrl"
	DatabaseKeyStartRedirect          = "startRedirect"
	DatabaseKeyPreserveHost           = "preserveHost"

	// OutpostPathPrefix is the path under which an Authentik proxy outpost serves its callback,
	// sign-in start, sign-out and static assets. It must be reachable on the protected host.
	OutpostPathPrefix = "/outpost.goauthentik.io"

	// StartRedirect modes. Empty means the auth server response is passed through unchanged.
	StartRedirectNone    = ""
	StartRedirectLocal   = "local"   // 302 to <protected host>/outpost.goauthentik.io/start?rd=<url>
	StartRedirectOutpost = "outpost" // 302 to <OutpostURL>/outpost.goauthentik.io/start?rd=<url>

	// AuthRequestTimeout bounds every outbound call made by forward auth.
	AuthRequestTimeout = 15 * time.Second
	// MaxAuthResponseBody caps how much of a non-success auth response is relayed to the client.
	MaxAuthResponseBody = 1 << 20

	HeaderXForwardedProto  = "X-Forwarded-Proto"
	HeaderXForwardedHost   = "X-Forwarded-Host"
	HeaderXForwardedURI    = "X-Forwarded-URI"
	HeaderXForwardedFor    = "X-Forwarded-For"
	HeaderXForwardedMethod = "X-Forwarded-Method"

	HeaderXOriginalURL    = "X-Original-URL"
	HeaderXOriginalIP     = "X-Original-IP"
	HeaderXOriginalMethod = "X-Original-Method"

	HeaderCookie   = "Cookie"
	HeaderLocation = "Location"

	HeaderUpgrade          = "Upgrade"
	HeaderConnection       = "Connection"
	HeaderTransferEncoding = "Transfer-Encoding"
	HeaderTE               = "TE"
	HeaderTrailers         = "Trailers"
	HeaderKeepAlive        = "Keep-Alive"
)

var (
	ErrInternalServerError = errors.New("internal server error")
	ErrUnauthorized        = errors.New("unauthorized")
	ErrOutpostHandled      = errors.New("outpost request handled")
)

var (
	doNotCopyHeaders = []string{
		HeaderUpgrade,
		HeaderConnection,
		HeaderTransferEncoding,
		HeaderTE,
		HeaderTrailers,
		HeaderKeepAlive,
	}
)
