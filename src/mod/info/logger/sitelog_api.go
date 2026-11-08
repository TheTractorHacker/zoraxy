package logger

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"imuslab.com/zoraxy/mod/utils"
)

// LoadSiteLogConfig reads the config file; a missing or malformed file yields the (disabled) defaults
func LoadSiteLogConfig(path string) SiteLogConfig {
	cfg := DefaultSiteLogConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	loaded := DefaultSiteLogConfig()
	if json.Unmarshal(b, &loaded) != nil || loaded.Validate() != nil {
		return cfg
	}
	return loaded
}

// SaveSiteLogConfig writes the config file
func SaveSiteLogConfig(path string, cfg SiteLogConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return err
	}
	js, _ := json.MarshalIndent(cfg, "", " ")
	return os.WriteFile(path, js, 0o644)
}

// HandleSiteLogConfig serves GET (current config) and POST (JSON body = new config) of /api/log/sites/config
func HandleSiteLogConfig(path string, sites *SiteLogs) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sites == nil {
			utils.SendErrorResponse(w, "file logging is disabled (-enablelog=false)")
			return
		}
		if r.Method == http.MethodPost {
			cfg := DefaultSiteLogConfig()
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&cfg); err != nil {
				utils.SendErrorResponse(w, "invalid JSON body")
				return
			}
			if err := sites.SetConfig(cfg); err != nil {
				utils.SendErrorResponse(w, err.Error())
				return
			}
			if err := SaveSiteLogConfig(path, sites.Config()); err != nil {
				utils.SendErrorResponse(w, "unable to save: "+err.Error())
				return
			}
		}
		js, _ := json.Marshal(sites.Config())
		utils.SendJSONResponse(w, string(js))
	}
}
