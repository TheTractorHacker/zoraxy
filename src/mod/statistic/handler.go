package statistic

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"imuslab.com/zoraxy/mod/utils"
)

/*
	Handler.go

	This script handles incoming request for loading the statistic of the day

*/

func (c *Collector) HandleTodayStatLoad(w http.ResponseWriter, r *http.Request) {

	fast, _ := utils.GetBool(r, "fast")
	d := c.GetCurrentDailySummary()
	if fast {
		//Only return the counter
		exported := DailySummaryExport{
			TotalRequest: atomic.LoadInt64(&d.TotalRequest),
			ErrorRequest: atomic.LoadInt64(&d.ErrorRequest),
			ValidRequest: atomic.LoadInt64(&d.ValidRequest),
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
