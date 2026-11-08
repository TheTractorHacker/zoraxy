package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	networkingapi.go

	Admin APIs for the per proxy rule networking options:
	  - client certificate (mTLS) policy        (upstream #442)
	  - path scoped rules                       (upstream #238 / #726)
	  - allowed direct peer CIDR set            (upstream #761)
	  - TLS on secondary listening ports        (upstream #1042)

	GET  /api/proxy/networking/get?ep=<rule>           all four settings of the rule
	POST /api/proxy/networking/clientcert              ep, config (JSON ClientCertConfig, empty Mode = off)
	POST /api/proxy/networking/clientcert/inspect      pem (CA bundle) -> subjects / validity, for the UI preview
	POST /api/proxy/networking/pathrules               ep, rules (JSON array of PathRule)
	POST /api/proxy/networking/peers                   ep, cidrs (JSON array of strings)
	POST /api/proxy/networking/secondarytls            ep, enable (bool)

	Every change is validated first, applied to the runtime with the same prepare / swap sequence as the WAF API and
	then persisted. Logic lives in mod/dynamicproxy (clientcert.go, pathrules.go, peerset.go, secondarytls.go).
*/

func RegisterNetworkingAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/proxy/networking/get", HandleNetworkingGet)
	authRouter.HandleFunc("/api/proxy/networking/clientcert", HandleNetworkingClientCert)
	authRouter.HandleFunc("/api/proxy/networking/clientcert/inspect", HandleNetworkingCAInspect)
	authRouter.HandleFunc("/api/proxy/networking/pathrules", HandleNetworkingPathRules)
	authRouter.HandleFunc("/api/proxy/networking/peers", HandleNetworkingPeers)
	authRouter.HandleFunc("/api/proxy/networking/secondarytls", HandleNetworkingSecondaryTLS)
	authRouter.HandleFunc("/api/proxy/defaultsite/logging", HandleDefaultSiteLogging)
}

// applyNetworkingChange applies mutate to a copy of the endpoint, prepares it, swaps it into the runtime and saves it
func applyNetworkingChange(rootNameOrMatchingDomain string, mutate func(ep *dynamicproxy.ProxyEndpoint) error) error {
	target, err := dynamicProxyRouter.LoadProxy(rootNameOrMatchingDomain)
	if err != nil {
		return err
	}
	updated := dynamicproxy.CopyEndpoint(target)
	if err := mutate(updated); err != nil {
		return err
	}
	ready, err := dynamicProxyRouter.PrepareProxyRoute(updated)
	if err != nil {
		return err
	}
	target.Remove()
	loadBalancer.ResetSessions()
	dynamicProxyRouter.AddProxyRouteToRuntime(ready)
	return SaveReverseProxyConfig(updated)
}

func networkingPostEndpoint(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return "", false
	}
	ep, err := utils.PostPara(r, "ep")
	if err != nil || ep == "" {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return "", false
	}
	return ep, true
}

func HandleNetworkingGet(w http.ResponseWriter, r *http.Request) {
	ep, err := utils.GetPara(r, "ep")
	if err != nil {
		utils.SendErrorResponse(w, "Target proxy rule not defined")
		return
	}
	target, err := dynamicProxyRouter.LoadProxy(ep)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	cc := target.ClientCert
	if cc == nil {
		cc = &dynamicproxy.ClientCertConfig{}
	}
	rules := target.PathRules
	if rules == nil {
		rules = []*dynamicproxy.PathRule{}
	}
	peers := target.AllowedPeerCIDRs
	if peers == nil {
		peers = []string{}
	}
	js, _ := json.Marshal(map[string]interface{}{
		"ClientCert":        cc,
		"PathRules":         rules,
		"AllowedPeerCIDRs":  peers,
		"SecondaryPortsTLS": target.SecondaryPortsTLS,
		"ListeningPorts":    target.ListeningPorts,
	})
	utils.SendJSONResponse(w, string(js))
}

func HandleNetworkingClientCert(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "config")
	if err != nil {
		utils.SendErrorResponse(w, "config not given")
		return
	}
	cfg := &dynamicproxy.ClientCertConfig{}
	if err := json.Unmarshal([]byte(raw), cfg); err != nil {
		utils.SendErrorResponse(w, "Invalid config: "+err.Error())
		return
	}
	cfg.Mode = strings.TrimSpace(cfg.Mode)
	if _, err := dynamicproxy.ValidateClientCertConfig(cfg); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		if cfg.Enabled() {
			e.ClientCert = cfg
		} else {
			e.ClientCert = nil
		}
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

// HandleNetworkingCAInspect lists the certificates of a pasted CA bundle so the admin can check what was uploaded
func HandleNetworkingCAInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return
	}
	raw, err := utils.PostPara(r, "pem")
	if err != nil {
		utils.SendErrorResponse(w, "pem not given")
		return
	}
	if _, err := dynamicproxy.ValidateClientCertConfig(&dynamicproxy.ClientCertConfig{Mode: dynamicproxy.ClientCertModeRequest, CAPEM: raw}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	type certInfo struct {
		Subject  string
		Issuer   string
		NotAfter string
		Expired  bool
		IsCA     bool
	}
	out := []certInfo{}
	rest := []byte(raw)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, certInfo{c.Subject.String(), c.Issuer.String(), c.NotAfter.Format("2006-01-02"), time.Now().After(c.NotAfter), c.IsCA})
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}

func HandleNetworkingPathRules(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "rules")
	if err != nil {
		utils.SendErrorResponse(w, "rules not given")
		return
	}
	rules := []*dynamicproxy.PathRule{}
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		utils.SendErrorResponse(w, "Invalid rules: "+err.Error())
		return
	}
	if err := dynamicproxy.ValidatePathRules(rules); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.PathRules = rules
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleNetworkingPeers(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	raw, err := utils.PostPara(r, "cidrs")
	if err != nil {
		utils.SendErrorResponse(w, "cidrs not given")
		return
	}
	cidrs := []string{}
	if err := json.Unmarshal([]byte(raw), &cidrs); err != nil {
		utils.SendErrorResponse(w, "Invalid list: "+err.Error())
		return
	}
	if err := dynamicproxy.ValidatePeerSet(cidrs); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.AllowedPeerCIDRs = cidrs
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleNetworkingSecondaryTLS(w http.ResponseWriter, r *http.Request) {
	ep, ok := networkingPostEndpoint(w, r)
	if !ok {
		return
	}
	enable, err := utils.PostBool(r, "enable")
	if err != nil {
		utils.SendErrorResponse(w, "enable not given")
		return
	}
	if err := applyNetworkingChange(ep, func(e *dynamicproxy.ProxyEndpoint) error {
		e.SecondaryPortsTLS = enable
		return nil
	}); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	//Restart the listeners of this rule that switch between HTTP and TLS
	dynamicProxyRouter.UpdateSecondaryListeners()
	utils.SendOK(w)
}

// HandleDefaultSiteLogging reads (GET) or sets (POST enable) the logging of default site requests (upstream #578).
// The lines are rate limited, see mod/dynamicproxy/defaultsitelog.go.
func HandleDefaultSiteLogging(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		enable, err := utils.PostBool(r, "enable")
		if err != nil {
			utils.SendErrorResponse(w, "enable not given")
			return
		}
		dynamicProxyRouter.SetDefaultSiteLogging(enable)
		sysdb.Write("settings", "logDefaultSite", enable)
		utils.SendOK(w)
		return
	}
	js, _ := json.Marshal(map[string]interface{}{
		"enabled": dynamicProxyRouter.DefaultSiteLoggingEnabled(),
		"logged":  dynamicProxyRouter.DefaultSiteLogStats(),
	})
	utils.SendJSONResponse(w, string(js))
}

// initUpstreamClientCertLoader lets upstreams present a client certificate (mTLS towards the backend) taken from the
// certificate store, by name (<name>.pem + <name>.key). The name was validated when the upstream was saved; it is checked again here.
func initUpstreamClientCertLoader() {
	loadbalance.UpstreamClientCertLoader = func(name string) (*tls.Certificate, error) {
		if name == "" || name != filepath.Base(name) || strings.HasPrefix(name, ".") {
			return nil, errors.New("invalid client certificate name")
		}
		pair, err := tls.LoadX509KeyPair(filepath.Join(tlsCertManager.CertStore, name+".pem"), filepath.Join(tlsCertManager.CertStore, name+".key"))
		if err != nil {
			return nil, err
		}
		return &pair, nil
	}
}
