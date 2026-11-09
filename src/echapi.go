package main

/*
	echapi.go

	Admin APIs for server side Encrypted Client Hello (mod/ech). Everything is off by default.

	GET  /api/ech/status                 settings, keys (no private material), the base64 ECHConfigList, a copy ready HTTPS record,
	                                     certificate check of the public name, HTTP/3 state and request counters
	POST /api/ech/settings               enabled, publicname, maxnamelength, rotatehours, retainhours
	POST /api/ech/rotate                 generate a new active key, the previous one becomes decrypt only
	POST /api/ech/retire                 id: stop advertising a key (keeps decrypting)
	POST /api/ech/delete                 id: remove a key
	POST /api/ech/export                 id: ECH PEM (contains the PRIVATE KEY, admin only, not available to viewers)
	POST /api/ech/import                 pem: add a key in ECH PEM format (decrypt only)
	GET  /api/ech/dnscheck               host, resolver (optional IP): compare the HTTPS record with the active config
	GET  /api/ech/domains                host (optional): per proxied host, classify the ECH config in the system and public resolver's HTTPS record
	GET  /api/ech/selfcheck              host (optional): a real local ECH handshake against the HTTPS listener (server side acceptance only)
*/

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/ech"
	"imuslab.com/zoraxy/mod/tlscert"
	"imuslab.com/zoraxy/mod/utils"
)

var echMgr *ech.Manager
var echStop chan bool

// initEch opens the ECH key store. It never fails startup: without it ECH is simply unavailable.
func initEch() {
	if echMgr != nil {
		return
	}
	m, err := ech.Open(filepath.Join(CONF_FOLDER, "ech"))
	if err != nil {
		SystemWideLogger.PrintAndLog("ech", "Unable to open the ECH key store, ECH is unavailable", err)
		return
	}
	echMgr = m
	if tlsCertManager != nil {
		tlsCertManager.OnServe = echServeHook
	}
	echStop = make(chan bool)
	go func(stop chan bool) {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				m.Maintain()
			case <-stop:
				return
			}
		}
	}(echStop)
}

func stopEch() {
	if echStop != nil {
		close(echStop)
		echStop = nil
	}
}

func RegisterEchAPIs(authRouter *auth.RouterDef) {
	authRouter.HandleFunc("/api/ech/status", HandleEchStatus)
	authRouter.HandleFunc("/api/ech/settings", HandleEchSettings)
	authRouter.HandleFunc("/api/ech/rotate", HandleEchRotate)
	authRouter.HandleFunc("/api/ech/retire", HandleEchRetire)
	authRouter.HandleFunc("/api/ech/delete", HandleEchDelete)
	authRouter.HandleFunc("/api/ech/export", HandleEchExport)
	authRouter.HandleFunc("/api/ech/import", HandleEchImport)
	authRouter.HandleFunc("/api/ech/dnscheck", HandleEchDNSCheck)
	authRouter.HandleFunc("/api/ech/selfcheck", HandleEchSelfCheck)
	authRouter.HandleFunc("/api/ech/domains", HandleEchDomains)
}

func echReady(w http.ResponseWriter) bool {
	if echMgr == nil {
		utils.SendErrorResponse(w, "ECH key store is not available")
		return false
	}
	return true
}

func echPost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		utils.SendErrorResponse(w, "Method not supported")
		return false
	}
	return echReady(w)
}

func HandleEchStatus(w http.ResponseWriter, r *http.Request) {
	if !echReady(w) {
		return
	}
	s := echMgr.Settings()
	list := echMgr.ConfigListBase64()
	h3 := dynamicProxyRouter != nil && dynamicProxyRouter.Option.EnableH3
	certName := s.PublicName
	if q, _ := utils.GetPara(r, "name"); q != "" {
		certName = strings.ToLower(strings.TrimSpace(q)) //pre-flight check of a name that is not saved yet
	}
	certCheck := echPublicNameCheck(certName)
	acc, plain := echMgr.Stats()
	outerTotal, outerBad := echMgr.OuterStats()
	out := map[string]interface{}{
		"Settings":        s,
		"Keys":            echMgr.Keys(),
		"ConfigList":      list,
		"RecordExample":   "",
		"PublicNameCert":  certCheck.Valid,
		"PublicNameCheck": certCheck,
		"OuterHandshakes": outerTotal,
		"OuterBadCert":    outerBad,
		"HTTP3Enabled":    h3,
		"TLSEnabled":      dynamicProxyRouter != nil && dynamicProxyRouter.Option.UseTls,
		"Accepted":        acc,
		"NotAccepted":     plain,
		"Records":         []ech.HostRecord{},
	}
	if list != "" {
		out["Records"] = ech.RecordsFor(echProxyHosts(), list, h3)
		out["RecordExample"] = ech.SVCBExample("www.example.com", list, h3)
	}
	js, _ := json.Marshal(out)
	utils.SendJSONResponse(w, string(js))
}

// echPublicNameCheck says whether Zoraxy really has a usable certificate for the public name.
// tlsCertManager.GetCertificateByHostname never fails (it falls back to the self-signed localhost certificate),
// so the answer comes from inspecting the certificate itself.
func echPublicNameCheck(name string) tlscert.HostCertCheck {
	if name == "" {
		return tlscert.HostCertCheck{State: tlscert.CertMissing, Reason: "No public name is set."}
	}
	if tlsCertManager == nil {
		return tlscert.HostCertCheck{Host: name, State: tlscert.CertMissing, Reason: "The certificate manager is not available."}
	}
	return tlsCertManager.CheckHostCertificate(name, time.Now())
}

// echServeHook watches the handshakes addressed to the ECH public name: those are what clients send after their ECH
// was rejected, and they validate the certificate against the public name. A broken certificate there shows up in
// Chrome as ERR_ECH_FALLBACK_CERTIFICATE_INVALID.
func echServeHook(sni string, cert *tls.Certificate, fallback bool) {
	if echMgr == nil {
		return
	}
	s := echMgr.Settings()
	if !s.Enabled || s.PublicName == "" || !strings.EqualFold(sni, s.PublicName) {
		return
	}
	chk := tlscert.EvaluateCertificate(cert, s.PublicName, fallback, time.Now())
	if echMgr.NoteOuterHandshake(chk.Valid) {
		SystemWideLogger.PrintAndLog("ech", "A handshake arrived for the ECH public name "+s.PublicName+" but the certificate served is not valid for it ("+chk.Reason+
			") Clients whose ECH was rejected will show ERR_ECH_FALLBACK_CERTIFICATE_INVALID. Install a valid certificate for the public name or change the public name.", nil)
	}
}

// HandleEchDomains compares the HTTPS records the system resolver and a public resolver return for every proxied host with Zoraxy's keys
func HandleEchDomains(w http.ResponseWriter, r *http.Request) {
	if !echReady(w) {
		return
	}
	hosts := []string{}
	for _, rec := range ech.RecordsFor(echProxyHosts(), "AA==", false) {
		hosts = append(hosts, rec.Host)
	}
	if h, _ := utils.GetPara(r, "host"); h != "" {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) > 253 || strings.ContainsAny(h, " /:@*") {
			utils.SendErrorResponse(w, "Invalid host name")
			return
		}
		hosts = []string{h}
	}
	if len(hosts) > 40 {
		hosts = hosts[:40]
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	js, _ := json.Marshal(echMgr.CheckDomains(ctx, hosts))
	utils.SendJSONResponse(w, string(js))
}

// echProxyHosts lists the host names of the proxy rules (and their aliases) that could carry an HTTPS record
func echProxyHosts() []string {
	hosts := []string{}
	if dynamicProxyRouter == nil {
		return hosts
	}
	for _, ep := range dynamicProxyRouter.GetProxyEndpointsAsMap() {
		hosts = append(hosts, ep.RootOrMatchingDomain)
		hosts = append(hosts, ep.MatchingDomainAlias...)
	}
	return hosts
}

// HandleEchSelfCheck performs a local ECH handshake with the active config against the HTTPS listener.
// It can only prove the server side; real browser acceptance depends on DNS and the client.
func HandleEchSelfCheck(w http.ResponseWriter, r *http.Request) {
	if !echReady(w) {
		return
	}
	list := echMgr.ConfigListBase64()
	if list == "" {
		utils.SendErrorResponse(w, "There is no active ECH key to test. Enable ECH with a public name first.")
		return
	}
	if dynamicProxyRouter == nil || !dynamicProxyRouter.Option.UseTls {
		utils.SendErrorResponse(w, "The HTTPS listener is not running in TLS mode, so there is nothing to test.")
		return
	}
	if !dynamicProxyRouter.Running {
		utils.SendErrorResponse(w, "The proxy listener is not running on port "+strconv.Itoa(dynamicProxyRouter.Option.Port)+" (is the port free and the proxy started?), so there is nothing to test.")
		return
	}
	host, _ := utils.GetPara(r, "host")
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		host = echMgr.Settings().PublicName
	}
	if host == "" || strings.ContainsAny(host, " /:") {
		utils.SendErrorResponse(w, "Invalid host name")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res := ech.SelfCheck(ctx, "127.0.0.1:"+strconv.Itoa(dynamicProxyRouter.Option.Port), host, list)
	w.Header().Set("Cache-Control", "no-store")
	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}

func HandleEchSettings(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	cur := echMgr.Settings()
	if v, err := utils.PostBool(r, "enabled"); err == nil {
		cur.Enabled = v
	}
	if v, err := utils.PostPara(r, "publicname"); err == nil {
		cur.PublicName = strings.ToLower(strings.TrimSpace(v))
	}
	for key, dst := range map[string]*int{"maxnamelength": &cur.MaxNameLength, "rotatehours": &cur.RotateEveryHours, "retainhours": &cur.RetainHours} {
		if v, err := utils.PostPara(r, key); err == nil && v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				utils.SendErrorResponse(w, key+" must be a number")
				return
			}
			*dst = n
		}
	}
	if err := echMgr.SetSettings(cur); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	if cur.Enabled {
		if chk := echPublicNameCheck(cur.PublicName); !chk.Valid {
			SystemWideLogger.PrintAndLog("ech", "ECH enabled, but the public name has no valid certificate: "+chk.Reason+" Clients whose ECH is rejected will fail with ERR_ECH_FALLBACK_CERTIFICATE_INVALID.", nil)
		}
	}
	utils.SendOK(w)
}

func HandleEchRotate(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	if _, err := echMgr.Rotate(); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleEchRetire(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	id, _ := utils.PostPara(r, "id")
	if err := echMgr.Retire(id); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleEchDelete(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	id, _ := utils.PostPara(r, "id")
	if err := echMgr.Delete(id); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleEchExport(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	id, _ := utils.PostPara(r, "id")
	pemText, err := echMgr.Export(id)
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	js, _ := json.Marshal(map[string]string{"PEM": pemText})
	utils.SendJSONResponse(w, string(js))
}

func HandleEchImport(w http.ResponseWriter, r *http.Request) {
	if !echPost(w, r) {
		return
	}
	pemText, _ := utils.PostPara(r, "pem")
	if _, err := echMgr.Import(pemText); err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func HandleEchDNSCheck(w http.ResponseWriter, r *http.Request) {
	if !echReady(w) {
		return
	}
	host, _ := utils.GetPara(r, "host")
	resolver, _ := utils.GetPara(r, "resolver")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	res, err := ech.CheckDNS(ctx, host, resolver, echMgr.ConfigListBase64())
	if err != nil {
		utils.SendErrorResponse(w, err.Error())
		return
	}
	js, _ := json.Marshal(res)
	utils.SendJSONResponse(w, string(js))
}

// echKeysCallback is the tls.Config hook handed to the router. It reads the manager per handshake, so enabling,
// rotating and retiring keys needs no listener restart.
func echKeysCallback() func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
	if echMgr == nil {
		return nil
	}
	return func(*tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) { return echMgr.TLSKeys(), nil }
}

func echObserveCallback() func(bool) {
	if echMgr == nil {
		return nil
	}
	return echMgr.Observe
}
