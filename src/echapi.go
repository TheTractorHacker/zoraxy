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
	certOK := false
	if s.PublicName != "" && tlsCertManager != nil {
		if _, _, err := tlsCertManager.GetCertificateByHostname(s.PublicName); err == nil {
			certOK = true
		}
	}
	acc, plain := echMgr.Stats()
	out := map[string]interface{}{
		"Settings":       s,
		"Keys":           echMgr.Keys(),
		"ConfigList":     list,
		"RecordExample":  "",
		"PublicNameCert": certOK,
		"HTTP3Enabled":   h3,
		"TLSEnabled":     dynamicProxyRouter != nil && dynamicProxyRouter.Option.UseTls,
		"Accepted":       acc,
		"NotAccepted":    plain,
	}
	if list != "" {
		out["RecordExample"] = ech.SVCBExample("www.example.com", list, h3)
	}
	js, _ := json.Marshal(out)
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
