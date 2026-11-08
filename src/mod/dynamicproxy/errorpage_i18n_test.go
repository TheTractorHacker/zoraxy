package dynamicproxy

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltinErrorPagesFollowAcceptLanguage(t *testing.T) {
	for _, tt := range []struct {
		tmpl   ErrorTemplateType
		status int
		lang   string
		want   string
	}{
		{ErrorTemplateForbidden, 403, "zh-CN", "您没有权限查看此目录或页面。"},
		{ErrorTemplateHostError, 404, "de", "Zielhost nicht gefunden"},
		{ErrorTemplateRPError, 521, "es-MX,es;q=0.9", "El servidor web está caído"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "http://x.example/", nil)
		r.Header.Set("Accept-Language", tt.lang)
		serveProxyRequestError(w, r, tt.status, nil, tt.tmpl)
		if w.Code != tt.status {
			t.Errorf("status %d, want %d", w.Code, tt.status)
		}
		if !strings.Contains(w.Body.String(), tt.want) {
			t.Errorf("%s page for %q misses %q", tt.lang, tt.lang, tt.want)
		}
		// default: untouched English
		w = httptest.NewRecorder()
		serveProxyRequestError(w, httptest.NewRequest("GET", "http://x.example/", nil), tt.status, nil, tt.tmpl)
		emb, _ := tt.tmpl.getTemplateContent()
		if w.Body.String() != string(emb) {
			t.Errorf("English page changed for template %d", tt.tmpl)
		}
	}
}
