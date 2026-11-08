package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	Upstreams.go

	This script handle upstream and load balancer
	related API
*/

// List upstreams from a endpoint
func ReverseProxyUpstreamList(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	activeUpstreams := targetEndpoint.ActiveOrigins
	inactiveUpstreams := targetEndpoint.InactiveOrigins
	// Sort the upstreams slice by weight, then by origin domain alphabetically
	sort.Slice(activeUpstreams, func(i, j int) bool {
		if activeUpstreams[i].Weight != activeUpstreams[j].Weight {
			return activeUpstreams[i].Weight > activeUpstreams[j].Weight
		}
		return activeUpstreams[i].OriginIpOrDomain < activeUpstreams[j].OriginIpOrDomain
	})

	sort.Slice(inactiveUpstreams, func(i, j int) bool {
		if inactiveUpstreams[i].Weight != inactiveUpstreams[j].Weight {
			return inactiveUpstreams[i].Weight > inactiveUpstreams[j].Weight
		}
		return inactiveUpstreams[i].OriginIpOrDomain < inactiveUpstreams[j].OriginIpOrDomain
	})

	//Live state of every upstream (health, in-flight requests, response time)
	now := time.Now()
	states := map[string]loadbalance.UpstreamState{}
	for _, u := range activeUpstreams {
		states[u.OriginIpOrDomain] = u.GetState(now, targetEndpoint.LoadBalanceConfig)
	}

	type UpstreamCombinedList struct {
		ActiveOrigins   []*loadbalance.Upstream
		InactiveOrigins []*loadbalance.Upstream
		States          map[string]loadbalance.UpstreamState //Keyed by OriginIpOrDomain, active upstreams only
	}

	js, _ := json.Marshal(UpstreamCombinedList{
		ActiveOrigins:   activeUpstreams,
		InactiveOrigins: inactiveUpstreams,
		States:          states,
	})
	utils.SendJSONResponse(w, string(js))
}

// Add an upstream to a given proxy upstream endpoint
func ReverseProxyUpstreamAdd(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	upstreamOrigin, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "upstream origin not set")
		return
	}

	//Response timeout in seconds, set to 0 for default
	respTimeout, err := utils.PostInt(r, "respt")
	if err != nil {
		respTimeout = 0
	}

	//Max concurrent connection to dpcore instance, set to 0 for default
	maxConn, err := utils.PostInt(r, "maxconn")
	if err != nil {
		maxConn = 0
	}

	requireTLS, _ := utils.PostBool(r, "tls")
	skipTlsValidation, _ := utils.PostBool(r, "tlsval")
	bpwsorg, _ := utils.PostBool(r, "bpwsorg")
	disableKeepAlive, _ := utils.PostBool(r, "nokeepalive")
	useH2C, _ := utils.PostBool(r, "h2c")
	preactivate, _ := utils.PostBool(r, "active")
	proxyProto, _ := utils.PostInt(r, "proxyproto") //0 off, 1 / 2 = PROXY protocol version
	clientCertName, _ := utils.PostPara(r, "clientcert")

	//Create a new upstream object
	newUpstream := loadbalance.Upstream{
		OriginIpOrDomain:         upstreamOrigin,
		RequireTLS:               requireTLS,
		SkipCertValidations:      skipTlsValidation,
		SkipWebSocketOriginCheck: bpwsorg,
		Weight:                   1,
		MaxConn:                  maxConn,
		RespTimeout:              int64(respTimeout),
		DisableKeepAlive:         disableKeepAlive,
		H2C:                      useH2C,
		ProxyProtocol:            proxyProto,
		ClientCertName:           strings.TrimSpace(clientCertName),
	}
	if err := newUpstream.ValidateTransportOptions(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Add the new upstream to endpoint
	err = targetEndpoint.AddUpstreamOrigin(&newUpstream, preactivate)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Save changes to configs
	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to save new upstream to proxy config", err)
		utils.SendErrorResponse(w, "Failed to save new upstream config")
		return
	}

	//Update Uptime Monitor
	UpdateUptimeMonitorTargets()

	utils.SendOK(w)
}

// Update the connection configuration of this origin
// pass in the whole new upstream origin json via "payload" POST variable
// for missing fields, original value will be used instead
func ReverseProxyUpstreamUpdate(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	//Editing upstream origin IP
	originIP, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "origin ip or matching address not set")
		return
	}
	originIP = strings.TrimSpace(originIP)

	//Update content payload
	payload, err := utils.PostPara(r, "payload")
	if err != nil {
		utils.SendErrorResponse(w, "update payload not set")
		return
	}

	isActive, _ := utils.PostBool(r, "active")

	targetUpstream, err := targetEndpoint.GetUpstreamOriginByMatchingIP(originIP)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Deep copy the upstream so other request handling goroutine won't be effected
	newUpstream := targetUpstream.Clone()

	//Overwrite the new value into the old upstream
	err = json.Unmarshal([]byte(payload), &newUpstream)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	if err := newUpstream.ValidateTransportOptions(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Replace the old upstream with the new one
	err = targetEndpoint.RemoveUpstreamOrigin(originIP)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	err = targetEndpoint.AddUpstreamOrigin(newUpstream, isActive)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}

	//Save changes to configs
	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to save upstream update to proxy config", err)
		utils.SendErrorResponse(w, "Failed to save updated upstream config")
		return
	}

	//Update Uptime Monitor
	UpdateUptimeMonitorTargets()
	utils.SendOK(w)
}

func ReverseProxyUpstreamSetPriority(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	weight, err := utils.PostInt(r, "weight")
	if err != nil {
		utils.SendErrorResponse(w, "priority not defined")
		return
	}

	if weight < 0 {
		utils.SendErrorResponse(w, "invalid weight given")
		return
	}

	//Editing upstream origin IP
	originIP, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "origin ip or matching address not set")
		return
	}
	originIP = strings.TrimSpace(originIP)

	editingUpstream, err := targetEndpoint.GetUpstreamOriginByMatchingIP(originIP)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to update upstream weight", err)
		utils.SendErrorResponse(w, "Failed to update upstream weight! (wrong origin?)")
		return
	}
	editingUpstream.Weight = weight
	// The editing upstream is a pointer to the runtime object
	// and the change of weight do not requre a respawn of the proxy object
	// so no need to remove & re-prepare the upstream on weight changes

	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to update upstream weight", err)
		utils.SendErrorResponse(w, "Failed to update upstream weight")
		return
	}

	utils.SendOK(w)
}

func ReverseProxyUpstreamDelete(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	//Editing upstream origin IP
	originIP, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "origin ip or matching address not set")
		return
	}
	originIP = strings.TrimSpace(originIP)

	if !targetEndpoint.UpstreamOriginExists(originIP) {
		utils.SendErrorResponse(w, "target upstream not found")
		return
	}

	err = targetEndpoint.RemoveUpstreamOrigin(originIP)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	//Save changes to configs
	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to remove upstream", err)
		utils.SendErrorResponse(w, "Failed to remove upstream from proxy rule")
		return
	}

	//Update uptime monitor
	UpdateUptimeMonitorTargets()

	utils.SendOK(w)
}

// LoadBalanceSettings is the view of the load balance config sent to the UI.
// Zero values are replaced with the defaults that are really applied
type LoadBalanceSettings struct {
	Algorithm          string
	HashKey            string
	ActiveHealthCheck  loadbalance.ActiveHealthCheck
	PassiveHealthCheck loadbalance.PassiveHealthCheck
	Retry              loadbalance.RetryConfig
	SlowStartSeconds   int
	ClientRules        []*loadbalance.ClientRule //Pin clients by CIDR / country to upstream groups
	Algorithms         []string                  //All valid algorithm names
}

// Get the load balancing, health check and retry settings of an endpoint
func ReverseProxyLoadBalanceGet(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	cfg := targetEndpoint.LoadBalanceConfig
	if cfg == nil {
		cfg = &loadbalance.Config{}
	}
	settings := LoadBalanceSettings{
		Algorithm:        cfg.GetAlgorithm(),
		HashKey:          cfg.HashKey,
		SlowStartSeconds: cfg.SlowStartSeconds,
		Algorithms:       loadbalance.AllAlgorithms,
		ClientRules:      cfg.ClientRules,
	}
	if settings.ClientRules == nil {
		settings.ClientRules = []*loadbalance.ClientRule{}
	}
	if cfg.ActiveHealthCheck != nil {
		settings.ActiveHealthCheck = cfg.ActiveHealthCheck.Normalized()
		settings.ActiveHealthCheck.Enabled = cfg.ActiveHealthCheck.Enabled
	} else {
		settings.ActiveHealthCheck = loadbalance.ActiveHealthCheck{}.Normalized()
	}
	if cfg.PassiveHealthCheck != nil {
		settings.PassiveHealthCheck = cfg.PassiveHealthCheck.Normalized()
		settings.PassiveHealthCheck.Enabled = cfg.PassiveHealthCheck.Enabled
	} else {
		settings.PassiveHealthCheck = loadbalance.PassiveHealthCheck{}.Normalized()
	}
	if cfg.Retry != nil {
		settings.Retry = cfg.Retry.Normalized()
		settings.Retry.Enabled = cfg.Retry.Enabled
	} else {
		settings.Retry = loadbalance.RetryConfig{}.Normalized()
	}
	if settings.Retry.ExtraMethods == nil {
		settings.Retry.ExtraMethods = []string{}
	}
	if settings.Retry.RetryStatuses == nil {
		settings.Retry.RetryStatuses = []int{}
	}

	js, _ := json.Marshal(settings)
	utils.SendJSONResponse(w, string(js))
}

// Set the load balancing, health check and retry settings of an endpoint
// The whole config is passed in as JSON via the "payload" POST variable
func ReverseProxyLoadBalanceSet(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	payload, err := utils.PostPara(r, "payload")
	if err != nil {
		utils.SendErrorResponse(w, "payload not set")
		return
	}

	newConfig := &loadbalance.Config{}
	if err := json.Unmarshal([]byte(payload), newConfig); err != nil {
		utils.SendErrorResponse(w, "invalid payload: "+err.Error())
		return
	}
	if err := newConfig.Validate(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	groupNames := []string{}
	for _, u := range append(append([]*loadbalance.Upstream{}, targetEndpoint.ActiveOrigins...), targetEndpoint.InactiveOrigins...) {
		groupNames = append(groupNames, u.OriginIpOrDomain)
	}
	if err := newConfig.ValidateClientRuleGroups(groupNames); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if newConfig.Algorithm == loadbalance.AlgoRandom {
		newConfig.Algorithm = "" //Store the default as empty so the config stays minimal
	}

	//Swap the pointer: requests being served keep using the previous config object
	targetEndpoint.LoadBalanceConfig = newConfig
	//Pushing to runtime also (re)starts or stops the active health checks
	targetEndpoint.UpdateToRuntime()

	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to save load balance settings", err)
		utils.SendErrorResponse(w, "Failed to save load balance settings")
		return
	}

	utils.SendOK(w)
}

// Set the draining state of an upstream. A draining upstream receives no new requests
// (and no new sticky sessions) while requests in flight finish normally
func ReverseProxyUpstreamSetDraining(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	originIP, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "origin ip or matching address not set")
		return
	}
	originIP = strings.TrimSpace(originIP)

	draining, err := utils.PostBool(r, "draining")
	if err != nil {
		utils.SendErrorResponse(w, "draining state not defined")
		return
	}

	editingUpstream, err := targetEndpoint.GetUpstreamOriginByMatchingIP(originIP)
	if err != nil {
		utils.SendErrorResponse(w, "target upstream not found")
		return
	}
	editingUpstream.Draining = draining

	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to update upstream draining state", err)
		utils.SendErrorResponse(w, "Failed to update upstream draining state")
		return
	}

	utils.SendOK(w)
}

// Set the maximum number of concurrent in-flight requests of an upstream, 0 for unlimited
func ReverseProxyUpstreamSetMaxInFlight(w http.ResponseWriter, r *http.Request) {
	endpoint, err := utils.PostPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "endpoint not defined")
		return
	}

	targetEndpoint, err := dynamicProxyRouter.LoadProxy(endpoint)
	if err != nil {
		utils.SendErrorResponse(w, "target endpoint not found")
		return
	}

	originIP, err := utils.PostPara(r, "origin")
	if err != nil {
		utils.SendErrorResponse(w, "origin ip or matching address not set")
		return
	}
	originIP = strings.TrimSpace(originIP)

	limit, err := utils.PostInt(r, "limit")
	if err != nil || limit < 0 {
		utils.SendErrorResponse(w, "invalid limit given")
		return
	}

	editingUpstream, err := targetEndpoint.GetUpstreamOriginByMatchingIP(originIP)
	if err != nil {
		utils.SendErrorResponse(w, "target upstream not found")
		return
	}
	editingUpstream.MaxInFlight = limit

	err = SaveReverseProxyConfig(targetEndpoint)
	if err != nil {
		SystemWideLogger.PrintAndLog("INFO", "Unable to update upstream max in-flight limit", err)
		utils.SendErrorResponse(w, "Failed to update upstream limit")
		return
	}

	utils.SendOK(w)
}
