package access

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/geodb"
	"imuslab.com/zoraxy/mod/info/logger"
)

type Options struct {
	Logger             logger.Logger
	ConfigFolder       string             //Path for storing config files
	TrustedProxiesFile string             //Path for storing trusted proxy IPs
	GeoDB              *geodb.Store       //For resolving country code
	Database           *database.Database //System key-value database

	/* Public IP monitoring */
	PublicIpCheckInterval int64 //in Seconds
	SkipPublicIPCheck     bool  //Never look up the public IP (tests / offline use); ServerPublicIP stays 127.0.0.1
}

type AccessRule struct {
	ID                             string
	Name                           string
	Desc                           string
	BlacklistEnabled               bool
	WhitelistEnabled               bool
	WhitelistAllowLocalAndLoopback bool //Allow local and loopback address to bypass whitelist
	TrustProxyHeadersOnly          bool //Only trust X-Forwarded-For and X-Real-IP headers from trusted proxies

	/* Whitelist Blacklist Table, value is comment if supported */
	WhiteListCountryCode *map[string]string
	WhiteListIP          *map[string]string
	BlackListContryCode  *map[string]string
	BlackListIP          *map[string]string

	parent  *Controller
	blIndex atomic.Value // *blacklistIndex, compiled IP blacklist lookup (see blacklist_index.go)
}

type TrustedProxy struct {
	IP   string
	Desc string
}

type Controller struct {
	ServerPublicIP    string
	DefaultAccessRule *AccessRule
	TrustedProxies    sync.Map // with structure of map[string]TrustedProxy
	ProxyAccessRule   *sync.Map
	Options           *Options
	CountryResolver   func(ip string) (string, error) `json:"-"` //Optional override of the GeoDB lookup (tests)

	//Internal
	publicIpTicker     *time.Ticker
	publicIpTickerStop chan bool
	trustedCIDRs       []*net.IPNet // Pre-parsed CIDR entries for fast lookup
	trustedCIDRMu      sync.RWMutex // Protects trustedCIDRs
}
