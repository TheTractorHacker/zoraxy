package main

/*
	i18napi.go

	Server-side default language of the admin UI, so the choice follows the instance instead of one browser.

	GET  /api/i18n/language                 -> {"language":"zh-CN","supported":["en","zh-CN",...]}  ("" = not chosen yet)
	POST /api/i18n/language  language=CODE  -> same document. An empty language clears the setting.

	The browser keeps its own explicit choice in localStorage (which wins); this value is the fallback used
	by browsers that have not chosen yet. Stored in the settings table under "uiLanguage".
*/

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/i18n"
	"imuslab.com/zoraxy/mod/utils"
)

const uiLanguageKey = "uiLanguage"

type uiLanguageState struct {
	Language  string   `json:"language"`
	Supported []string `json:"supported"`
}

func currentUILanguage() uiLanguageState {
	lang := ""
	if sysdb != nil {
		sysdb.Read("settings", uiLanguageKey, &lang)
	}
	if i18n.Normalize(lang) != lang { //stale / hand edited value
		lang = ""
	}
	return uiLanguageState{Language: lang, Supported: i18n.Supported}
}

func HandleUILanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		lang, _ := utils.PostPara(r, "language")
		if lang != "" {
			if i18n.Normalize(lang) != lang {
				utils.SendErrorResponse(w, "unsupported language")
				return
			}
		}
		if sysdb == nil {
			utils.SendErrorResponse(w, "database not available")
			return
		}
		if err := sysdb.Write("settings", uiLanguageKey, lang); err != nil {
			utils.SendErrorResponse(w, "unable to save")
			return
		}
	}
	js, _ := json.Marshal(currentUILanguage())
	utils.SendJSONResponse(w, string(js))
}
