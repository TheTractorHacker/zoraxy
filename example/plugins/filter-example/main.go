package main

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"regexp"
	"strconv"

	plugin "example.com/zoraxy/filter-example/mod/zoraxy_plugin"
)

/*
	Filter Example

	Demonstrates the Zoraxy request / response hooks:

	- pre_auth stage:  blocks requests whose User-Agent matches a regular expression
	                   (a tiny bot filter) and tags every other request with a header.
	                   Runs before the WAF, CAPTCHA and authentication.
	- response stage:  adds security headers to every response.

	Assign the plugin to an HTTP proxy rule with a tag (Plugins page) or enable
	"Apply to all HTTP proxy rules" in the plugin list.

	Override the pattern with the environment variable FILTER_EXAMPLE_UA_REGEX.
*/

const (
	UI_PATH      = "/ui"
	FILTER_PATH  = "/filter"
	defaultRegex = `(?i)(sqlmap|nikto|masscan|badbot)`
)

func main() {
	runtimeCfg, err := plugin.ServeAndRecvSpec(&plugin.IntroSpect{
		ID:            "org.aroz.zoraxy.filter-example",
		Name:          "Filter Example",
		Author:        "aroz.org",
		AuthorContact: "https://aroz.org",
		Description:   "Example pre-auth User-Agent filter and response header adder using the Zoraxy hook API.",
		URL:           "https://zoraxy.aroz.org",
		Type:          plugin.PluginType_Router,
		VersionMajor:  1,
		VersionMinor:  0,
		VersionPatch:  0,

		UIPath: UI_PATH,

		Hooks: &plugin.HookSettings{
			Version:           plugin.HookAPIVersion,
			Stages:            []plugin.HookStage{plugin.HookStagePreAuth, plugin.HookStageResponse},
			FilterRequestPath: FILTER_PATH,
			Priority:          10,
			TimeoutMs:         500,
			FailurePolicy:     plugin.FailureOpen, // never block traffic just because this example is down
		},
	})
	if err != nil {
		panic(err)
	}

	pattern := os.Getenv("FILTER_EXAMPLE_UA_REGEX")
	if pattern == "" {
		pattern = defaultRegex
	}
	uaRegex, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}

	// Filter endpoint: called by Zoraxy at the registered stages.
	// NewFilterHandler verifies the token Zoraxy passes in runtimeCfg.InvokeToken,
	// so other local processes cannot call this endpoint.
	http.Handle(FILTER_PATH, plugin.NewFilterHandler(runtimeCfg.InvokeToken, func(fr *plugin.FilterRequest) *plugin.FilterVerdict {
		switch fr.Stage {
		case plugin.HookStagePreAuth:
			if ua := fr.HeaderValue("User-Agent"); uaRegex.MatchString(ua) {
				return plugin.Deny(http.StatusForbidden, "Forbidden").WithReason("blocked User-Agent " + ua)
			}
			return plugin.ModifyRequestHeaders(plugin.HeaderOps{
				Set: map[string]string{"X-Filter-Example": "checked"},
			})
		case plugin.HookStageResponse:
			return plugin.ModifyResponseHeaders(plugin.HeaderOps{
				Set: map[string]string{
					"X-Content-Type-Options": "nosniff",
					"Referrer-Policy":        "strict-origin-when-cross-origin",
				},
				Remove: []string{"X-Powered-By"},
			})
		}
		return plugin.Allow()
	}))

	http.HandleFunc(UI_PATH+"/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<h3>Filter Example</h3><p>Blocking User-Agents matching: <code>%s</code></p>", html.EscapeString(pattern))
	})

	addr := "127.0.0.1:" + strconv.Itoa(runtimeCfg.Port)
	fmt.Println("Filter example started at http://" + addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}
