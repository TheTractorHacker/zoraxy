package access

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
)

// Check both blacklist and whitelist for access for both geoIP and ip / CIDR ranges
func (s *AccessRule) AllowIpAccess(ipaddr string) bool {
	if s.IsBlacklisted(ipaddr) {
		return false
	}

	return s.IsWhitelisted(ipaddr)
}

// Check both blacklist and whitelist for access using net.Conn
func (s *AccessRule) AllowConnectionAccess(conn net.Conn) bool {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return s.AllowIpAccess(addr.IP.String())
	}
	return true
}

// Toggle blacklist
func (s *AccessRule) ToggleBlacklist(enabled bool) {
	s.BlacklistEnabled = enabled
	s.SaveChanges()
}

// Toggel whitelist
func (s *AccessRule) ToggleWhitelist(enabled bool) {
	s.WhitelistEnabled = enabled
	s.SaveChanges()
}

// Toggle whitelist loopback
func (s *AccessRule) ToggleAllowLoopback(enabled bool) {
	s.WhitelistAllowLocalAndLoopback = enabled
	s.SaveChanges()
}

// Toggle trust proxy headers only
func (s *AccessRule) ToggleTrustProxy(enabled bool) {
	s.TrustProxyHeadersOnly = enabled
	s.SaveChanges()
}

/*
Check if a IP address is blacklisted, in either country or IP blacklist
IsBlacklisted default return is false (allow access)
*/
func (s *AccessRule) IsBlacklisted(ipAddr string) bool {
	if !s.BlacklistEnabled {
		//Blacklist not enabled. Always return false
		return false
	}

	if ipAddr == "" {
		//Unable to get the target IP address
		return false
	}

	//Explicit IP / CIDR / wildcard rules never depend on GeoIP, check them first
	if s.IsIPBlacklisted(ipAddr) {
		return true
	}

	//Country rules. A lookup failure is logged and fails open for the country
	//decision only (it never skips the IP rules above)
	countryCode, err := s.resolveCountry(ipAddr)
	if err != nil {
		s.logGeoError("blacklist", ipAddr, err)
		return false
	}

	return s.IsCountryCodeBlacklisted(countryCode)
}

/*
IsWhitelisted check if a given IP address is in the current
server's white list.

When the whitelist is enabled, an unresolvable country
code fails closed (only explicit IP rules can allow it)
*/
func (s *AccessRule) IsWhitelisted(ipAddr string) bool {
	if !s.WhitelistEnabled {
		//Whitelist not enabled. Always return true (allow access)
		return true
	}

	if ipAddr == "" {
		//Unable to get the target IP address, assume ok
		return true
	}

	//Explicit IP / CIDR rules do not depend on GeoIP
	if s.IsIPWhitelisted(ipAddr) {
		return true
	}

	countryCode, err := s.resolveCountry(ipAddr)
	if err != nil {
		//Fail closed: a lookup error must never allow-list an address
		s.logGeoError("whitelist", ipAddr, err)
		return false
	}

	return s.IsCountryCodeWhitelisted(countryCode)
}

/* Utilities function */

// resolveCountry resolves the ISO country code of an IP, using the
// override resolver if set (tests), otherwise the GeoDB
func (s *AccessRule) resolveCountry(ipAddr string) (string, error) {
	if s.parent == nil || s.parent.Options == nil {
		return "", errors.New("access rule detached from controller")
	}
	if s.parent.CountryResolver != nil {
		return s.parent.CountryResolver(ipAddr)
	}
	if s.parent.Options.GeoDB == nil {
		return "", errors.New("geoip database not available")
	}
	info, err := s.parent.Options.GeoDB.ResolveCountryCodeFromIP(ipAddr)
	if err != nil {
		return "", err
	}
	return info.CountryIsoCode, nil
}

func (s *AccessRule) logGeoError(list string, ipAddr string, err error) {
	if s.parent != nil && s.parent.Options != nil {
		s.parent.Options.Logger.PrintAndLog("Access", "GeoIP lookup failed during "+list+" check for "+ipAddr+", country rules skipped", err)
	}
}

// Update the current access rule to json file
func (s *AccessRule) SaveChanges() error {
	if s.parent == nil {
		return errors.New("save failed: access rule detached from controller")
	}
	saveTarget := filepath.Join(s.parent.Options.ConfigFolder, s.ID+".json")
	js, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}

	err = os.WriteFile(saveTarget, js, 0775)
	return err
}

// Delete this access rule, this will only delete the config file.
// for runtime delete, use DeleteAccessRuleByID from parent Controller
func (s *AccessRule) DeleteConfigFile() error {
	saveTarget := filepath.Join(s.parent.Options.ConfigFolder, s.ID+".json")
	return os.Remove(saveTarget)
}

// Delete the access rule by given ID
func (c *Controller) DeleteAccessRuleByID(accessRuleID string) error {
	targetAccessRule, err := c.GetAccessRuleByID(accessRuleID)
	if err != nil {
		return err
	}

	//Delete config file associated with this access rule
	err = targetAccessRule.DeleteConfigFile()
	if err != nil {
		return err
	}

	//Delete the access rule in runtime
	c.ProxyAccessRule.Delete(accessRuleID)
	return nil
}

// Create a deep copy object of the access rule list
func deepCopy(valueList map[string]string) map[string]string {
	result := map[string]string{}
	js, _ := json.Marshal(valueList)
	json.Unmarshal(js, &result)
	return result
}
