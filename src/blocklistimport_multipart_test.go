package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/access"
)

// The admin UI sends the import form as multipart/form-data (FormData, also for pasted text and uploaded files).
func blPostMultipart(t *testing.T, h http.HandlerFunc, fields map[string]string, file string) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	if file != "" {
		fw, _ := mw.CreateFormFile("file", "list.txt")
		fw.Write([]byte(file))
	}
	mw.Close()
	req := httptest.NewRequest("POST", "/x", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	h(w, req)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func TestBlocklistImportAPIMultipart(t *testing.T) {
	rule := setupBlocklistImportTest(t)
	apply := func(w http.ResponseWriter, r *http.Request) { handleBlocklistImport(w, r, false) }
	out := blPostMultipart(t, apply, map[string]string{"id": "default", "list": "blacklist", "text": "1.1.1.1\n2.2.2.0/24\n"}, "")
	if out["error"] != nil || out["accepted"] != float64(2) || rule.IPListSize(access.IPListBlack) != 2 {
		t.Fatalf("multipart paste = %v", out)
	}
	out = blPostMultipart(t, apply, map[string]string{"id": "default", "list": "whitelist"}, "3.3.3.3\n")
	if out["error"] != nil || rule.IPListSize(access.IPListWhite) != 1 {
		t.Fatalf("multipart file upload = %v", out)
	}
}
