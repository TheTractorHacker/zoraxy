package dynamicproxy

// BlockObserver, when set, is called for every request the WAF blocked (site = proxy rule key).
// It feeds the notification centre's WAF spike detection and must not block.
var BlockObserver func(site string, forwardType string)
