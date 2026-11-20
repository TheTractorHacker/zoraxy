package statistic

import (
	"encoding/json"
	"net/http"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Handler.go

	This script handles incoming request for loading the statistic of the day

*/

func (c *Collector) HandleTodayStatLoad(w http.ResponseWriter, r *http.Request) {

	fast, _ := utils.GetBool(r, "fast")
	d := c.DailySummary
	if fast {
		//Only return the counter
		exported := DailySummaryExport{
			TotalRequest: d.TotalRequest,
			ErrorRequest: d.ErrorRequest,
			ValidRequest: d.ValidRequest,
		}
		js, _ := json.Marshal(exported)
		utils.SendJSONResponse(w, string(js))
	} else {
		//Return everything
		exported := c.GetExportSummary()
		js, _ := json.Marshal(exported)
		utils.SendJSONResponse(w, string(js))
	}

}

// Handle read / write of the "exclude blocked requests" setting
// GET: return the current value as a JSON boolean
// POST: set the value with the "exclude" parameter (true / false)
func (c *Collector) HandleExcludeBlockedSetting(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		exclude, err := utils.PostBool(r, "exclude")
		if err != nil {
			utils.SendErrorResponse(w, "invalid exclude value")
			return
		}
		if err := c.SetExcludeBlocked(exclude); err != nil {
			utils.SendErrorResponse(w, err.Error())
			return
		}
		utils.SendOK(w)
		return
	}

	js, _ := json.Marshal(c.GetExcludeBlocked())
	utils.SendJSONResponse(w, string(js))
}
