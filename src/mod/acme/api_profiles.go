package acme

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	api_profiles.go

	HTTP handlers (admin authenticated by the caller) for:
	  key type default, CA profiles, DNS credential profiles, single certificate renew with log.
*/

func sendJSON(w http.ResponseWriter, v any) {
	js, _ := json.Marshal(v)
	utils.SendJSONResponse(w, string(js))
}

// hasPerCertDNSCreds reports whether DNS provider + credentials were stored for this certificate name
func (a *ACMEHandler) hasPerCertDNSCreds(certName string) bool {
	if a.Database == nil || !a.Database.TableExists("acme") {
		return false
	}
	return a.Database.KeyExists("acme", certName+"_dns_provider") && a.Database.KeyExists("acme", certName+"_dns_credentials")
}

// BuiltinCANames lists the CAs shipped in ca.json (production names), sorted.
func BuiltinCANames() []string {
	names := make([]string, 0, len(caDef.Production))
	for n := range caDef.Production {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// HandleKeyType: GET returns {default, options}; POST set=<key type> stores the default ("" resets).
func (a *ACMEHandler) HandleKeyType(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		v, _ := utils.PostPara(r, "set")
		if err := a.SetDefaultKeyType(v); err != nil {
			utils.SendErrorResponse(w, jsonEscape(err.Error()))
			return
		}
		utils.SendOK(w)
		return
	}
	sendJSON(w, map[string]any{"default": a.DefaultKeyTypePref(), "options": KeyTypeNames})
}

// HandleCAProfiles: GET lists (secrets masked) with the built-in CA names; POST op=save|delete.
func (a *ACMEHandler) HandleCAProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		op, _ := utils.PostPara(r, "op")
		switch op {
		case "save":
			p := CAProfile{}
			p.ID, _ = utils.PostPara(r, "id")
			p.Name, _ = utils.PostPara(r, "name")
			p.DirectoryURL, _ = utils.PostPara(r, "directoryURL")
			p.EABKid, _ = utils.PostPara(r, "eabKid")
			p.EABHmac, _ = utils.PostPara(r, "eabHmac")
			p.Profile, _ = utils.PostPara(r, "profile")
			p.SkipTLS, _ = utils.PostBool(r, "skipTLS")
			id, err := a.SaveCAProfile(p)
			if err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			sendJSON(w, map[string]string{"id": id})
		case "delete":
			id, _ := utils.PostPara(r, "id")
			if err := a.DeleteCAProfile(id); err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			utils.SendOK(w)
		default:
			utils.SendErrorResponse(w, "invalid operation")
		}
		return
	}
	list := a.ListCAProfiles()
	masked := make([]CAProfile, 0, len(list))
	for _, p := range list {
		masked = append(masked, p.Masked())
	}
	sendJSON(w, map[string]any{"profiles": masked, "builtin": BuiltinCANames()})
}

// HandleDNSProfiles: GET lists (secrets masked) with the default id; POST op=save|delete|setDefault.
func (a *ACMEHandler) HandleDNSProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		op, _ := utils.PostPara(r, "op")
		switch op {
		case "save":
			p := DNSProfile{}
			p.ID, _ = utils.PostPara(r, "id")
			p.Name, _ = utils.PostPara(r, "name")
			p.Provider, _ = utils.PostPara(r, "provider")
			p.Credentials, _ = utils.PostPara(r, "credentials")
			p.DNSServers, _ = utils.PostPara(r, "dnsServers")
			id, err := a.SaveDNSProfile(p)
			if err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			sendJSON(w, map[string]string{"id": id})
		case "delete":
			id, _ := utils.PostPara(r, "id")
			if err := a.DeleteDNSProfile(id); err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			utils.SendOK(w)
		case "setDefault":
			id, _ := utils.PostPara(r, "id")
			if err := a.SetDefaultDNSProfile(id); err != nil {
				utils.SendErrorResponse(w, jsonEscape(err.Error()))
				return
			}
			utils.SendOK(w)
		default:
			utils.SendErrorResponse(w, "invalid operation")
		}
		return
	}
	list := a.ListDNSProfiles()
	masked := make([]DNSProfile, 0, len(list))
	for _, p := range list {
		masked = append(masked, p.Masked())
	}
	sendJSON(w, map[string]any{"profiles": masked, "default": a.DefaultDNSProfileID()})
}

// RenewOne renews a single certificate by its store name using the settings remembered in its
// metadata (CA, challenge type, key type, saved profiles). It returns the operation log.
func (a *AutoRenewer) RenewOne(certName string) ([]string, error) {
	certName = strings.TrimSpace(certName)
	if certName == "" || certName != filepath.Base(certName) || strings.ContainsAny(certName, `/\`) {
		return nil, os.ErrInvalid
	}
	pemPath := filepath.Join(a.CertFolder, certName+".pem")
	domains, err := ExtractDomainsFromPEM(pemPath)
	if err != nil || len(domains) == 0 {
		return nil, errNoDomains
	}
	info, err := LoadCertInfoJSON(filepath.Join(a.CertFolder, certName+".json"))
	if err != nil {
		info = &CertificateInfoJSON{}
		if ca, cerr := ExtractIssuerNameFromPEM(pemPath); cerr == nil {
			info.AcmeName = ca
		}
	}
	if info.IsExternallyManaged() {
		return nil, errExternallyManaged
	}
	if info.PropTimeout == 0 {
		info.PropTimeout = 300
	}
	_, lines, err := a.AcmeHandler.ObtainCertCapture(domains, certName, a.RenewerConfig.Email, info.AcmeName, info.AcmeUrl, info.SkipTLS, info.UseDNS, info.PropTimeout, strings.Join(info.DNSServers, ","), info.DisableRecursiveNssCheck, info.DisableAuthoritativeNssCheck, ObtainOptions{
		KeyType: info.KeyType, Profile: info.AcmeProfile, CAProfileID: info.CAProfileID, DNSProfileID: info.DNSProfileID,
	})
	return lines, err
}

// HandleRenewCertNow: POST cert=<store name>. Responds {ok, log[], error}.
func (a *AutoRenewer) HandleRenewCertNow(w http.ResponseWriter, r *http.Request) {
	name, err := utils.PostPara(r, "cert")
	if err != nil {
		utils.SendErrorResponse(w, "cert not set")
		return
	}
	if a.RenewerConfig.Email == "" {
		utils.SendErrorResponse(w, "ACME email is not set (ACME page)")
		return
	}
	lines, rerr := a.RenewOne(name)
	res := map[string]any{"ok": rerr == nil, "log": lines}
	if lines == nil {
		res["log"] = []string{}
	}
	if rerr != nil {
		res["error"] = rerr.Error()
	}
	sendJSON(w, res)
}
