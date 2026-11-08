package dynamicproxy

import (
	"context"
	"net/http"
)

func contextWithOpsState(r *http.Request, st *opsState) context.Context {
	return context.WithValue(r.Context(), opsStateKey{}, st)
}

func opsStateFrom(r *http.Request) *opsState {
	st, _ := r.Context().Value(opsStateKey{}).(*opsState)
	return st
}
