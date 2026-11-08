package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/tlscert"
	"imuslab.com/zoraxy/mod/utils"
)

/*
	certinventory.go

	Certificate list extras: which proxy rules use which certificate, and the optional watched
	certificate directory (-certs_dir).
*/

var certMapDirWatcher *tlscert.MapDirWatcher

// initCertMapDir starts the -certs_dir watcher when the flag is set.
func initCertMapDir() {
	if *certsMapDir == "" {
		return
	}
	certMapDirWatcher = &tlscert.MapDirWatcher{
		Dir:      *certsMapDir,
		Interval: time.Duration(*certsMapInterval) * time.Second,
		Manager:  tlsCertManager,
		Logf:     func(f string, a ...any) { SystemWideLogger.Println(fmt.Sprintf(f, a...)) },
	}
	certMapDirWatcher.Start()
	SystemWideLogger.PrintAndLog("certs-dir", "Watching "+*certsMapDir+" for certificates", nil)
}

// handleCertUsage returns {certName: [hostnames of proxy rules using it]} for the certificate list.
func handleCertUsage(w http.ResponseWriter, r *http.Request) {
	usage := map[string][]string{}
	add := func(host string) {
		pub, _, err := tlsCertManager.GetCertificateByHostname(host)
		if err != nil || pub == "" {
			return
		}
		name := strings.TrimSuffix(filepath.Base(pub), filepath.Ext(pub))
		if name == "localhost" {
			return // built in fallback, not a stored certificate
		}
		for _, h := range usage[name] {
			if h == host {
				return
			}
		}
		usage[name] = append(usage[name], host)
	}
	dynamicProxyRouter.ProxyEndpoints.Range(func(_, value interface{}) bool {
		ept, ok := value.(*dynamicproxy.ProxyEndpoint)
		if !ok || ept == nil {
			return true
		}
		add(ept.RootOrMatchingDomain)
		for _, alias := range ept.MatchingDomainAlias {
			if alias != "" {
				add(alias)
			}
		}
		return true
	})
	for k := range usage {
		sort.Strings(usage[k])
	}
	js, _ := json.Marshal(usage)
	utils.SendJSONResponse(w, string(js))
}
