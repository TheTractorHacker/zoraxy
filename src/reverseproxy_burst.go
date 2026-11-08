package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"imuslab.com/zoraxy/mod/utils"
)

// rateLimitBurstFromRequest reads the optional "rateburst" form parameter (max
// burst size in requests, 0 = same as the rate). When the parameter is absent
// or empty the current value is returned unchanged, so old clients and
// existing configs keep their behaviour.
func rateLimitBurstFromRequest(r *http.Request, current int64) (int64, error) {
	raw, _ := utils.PostPara(r, "rateburst")
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return current, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("invalid rate limit burst, must be a number >= 0")
	}
	return n, nil
}
