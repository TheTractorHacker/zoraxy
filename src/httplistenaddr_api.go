package main

/*
	httplistenaddr_api.go

	Admin API for the address of the optional plain HTTP listener (":80" by default).

	GET  /api/proxy/httpListenAddr             -> {"config","default","runtime"}
	POST /api/proxy/httpListenAddr  addr=host:port   (empty addr resets to the default)

	Stored in the "settings" table under the key "httpListenAddr". A change restarts
	the proxy service, like the neighbouring "listen on port 80" toggle.
*/

import (
	"encoding/json"
	"net/http"
	"strings"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/netutils"
	"imuslab.com/zoraxy/mod/utils"
)

// loadHttpListenAddr reads the persisted plain HTTP listener address, falling back to ":80"
func loadHttpListenAddr() string {
	addr := ""
	if sysdb != nil {
		sysdb.Read("settings", "httpListenAddr", &addr)
	}
	if _, _, err := dynamicproxy.ParseHttpListenAddr(addr); err != nil {
		return dynamicproxy.DefaultHttpListenAddr
	}
	return dynamicproxy.NormalizeHttpListenAddr(addr)
}

// httpListenPortOccupied reports whether the configured plain HTTP port already answers on loopback
func httpListenPortOccupied(addr string) bool {
	_, port, err := dynamicproxy.ParseHttpListenAddr(addr)
	if err != nil {
		port = 80
	}
	return netutils.CheckIfPortOccupied(port)
}

func HandleHttpListenAddr(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		js, _ := json.Marshal(map[string]string{
			"config":  loadHttpListenAddr(),
			"default": dynamicproxy.DefaultHttpListenAddr,
			"runtime": dynamicProxyRouter.BoundHttpAddr(),
		})
		utils.SendJSONResponse(w, string(js))
	case http.MethodPost:
		addr, _ := utils.PostPara(r, "addr")
		addr = strings.TrimSpace(addr)
		if addr == "" {
			addr = dynamicproxy.DefaultHttpListenAddr
		}
		if err := dynamicproxy.ValidateHttpListenAddr(addr, *webUIPort, dynamicProxyRouter.Option.Port); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		if addr == loadHttpListenAddr() {
			utils.SendOK(w)
			return
		}
		enabled := false
		sysdb.Read("settings", "listenP80", &enabled)
		if enabled && httpListenPortOccupied(addr) {
			utils.SendErrorResponse(w, "That port is already used by another service")
			return
		}
		sysdb.Write("settings", "httpListenAddr", addr)
		SystemWideLogger.Println("Plain HTTP listener address set to " + addr)
		dynamicProxyRouter.UpdateHttpListenAddr(addr)
		utils.SendOK(w)
	default:
		http.Error(w, "405 - Method not allowed", http.StatusMethodNotAllowed)
	}
}
