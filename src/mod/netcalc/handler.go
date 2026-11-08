package netcalc

import (
	"encoding/json"
	"net/http"
)

// HandleNetCalc serves GET /api/tools/netcalc?q=<query> (authenticated by the caller's router).
// The response is the Result JSON, or {"error": "..."}.
func HandleNetCalc(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed"})
		return
	}
	res, err := Calculate(r.URL.Query().Get("q"))
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}
