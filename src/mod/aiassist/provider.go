package aiassist

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
)

/*
	Plain net/http clients, no SDKs.

	Anthropic: POST {endpoint}/v1/messages with x-api-key and anthropic-version. Structured output
	is obtained with a tool whose input_schema is the result schema; the reply is read from the
	tool_use block. tool_choice is "auto" with an explicit instruction (forced tool_choice is rejected
	by the newest models); a reply without a tool_use block is an error. No thinking, no sampling
	parameters, no streaming.

	OpenAI compatible: POST {endpoint}/chat/completions with response_format json_schema (and a
	json_object fallback when the server rejects it). The reply is parsed defensively.
*/

const (
	anthropicVersion = "2023-06-01"
	userAgent        = "zoraxy-aiassist/1"
	maxResponseBytes = 1 << 20
)

// Response is a parsed provider reply.
type Response struct {
	JSON         []byte // the structured result, still untrusted
	InputTokens  int64
	OutputTokens int64
}

// providerError never contains request data or the key.
//
// unbilled is true only when the provider cannot have processed (and billed) the request: the
// request was never fully written (dial, DNS, TLS errors, bad endpoint) or the provider answered
// with a clean refusal (4xx other than 408/425, or a redirect). Every other failure after the
// request was sent (cancel, timeout, oversized or unparsable reply, 5xx) is billed at the
// reservation estimate, see Service.call.
type providerError struct {
	msg      string
	unbilled bool
}

func (e *providerError) Error() string { return e.msg }

func perr(format string, a ...any) error { return &providerError{msg: fmt.Sprintf(format, a...)} }

func perrUnbilled(format string, a ...any) error {
	return &providerError{msg: fmt.Sprintf(format, a...), unbilled: true}
}

// cleanRefusal is true for HTTP statuses where the provider rejected the request without running it.
func cleanRefusal(status int) bool {
	return status >= 300 && status < 500 && status != 408 && status != 425
}

func doJSON(ctx context.Context, hc *http.Client, url string, hdr map[string]string, body any) ([]byte, int, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, 0, perrUnbilled("invalid endpoint")
	}
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(i httptrace.WroteRequestInfo) {
		if i.Err == nil {
			wrote.Store(true)
		}
	}})
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		// net/http errors carry the URL; strip it down to the cause without the key (it is only in a header)
		var ue interface{ Unwrap() error }
		if errors.As(err, &ue) && ue.Unwrap() != nil {
			err = ue.Unwrap()
		}
		if !wrote.Load() { // nothing was sent: dial, DNS, TLS or guard error
			return nil, 0, perrUnbilled("request failed: %s", capRunes(err.Error(), 200))
		}
		return nil, 0, perr("request failed: %s", capRunes(err.Error(), 200))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, perr("reading the reply failed")
	}
	if len(raw) > maxResponseBytes {
		return nil, resp.StatusCode, perr("reply is larger than %d bytes", maxResponseBytes)
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, resp.StatusCode, perrUnbilled("the endpoint answered with a redirect, which is not followed")
	}
	return raw, resp.StatusCode, nil
}

func apiErrorText(raw []byte, status int) error {
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	msg := capRunes(stripInvisible(e.Error.Message), 160)
	mk := perr
	if cleanRefusal(status) {
		mk = perrUnbilled
	}
	if msg == "" {
		return mk("provider returned HTTP %d", status)
	}
	return mk("provider returned HTTP %d: %s", status, msg)
}

func callAnthropic(ctx context.Context, hc *http.Client, base, key, model string, o *Outbound) (*Response, error) {
	body := map[string]any{
		"model":       model,
		"max_tokens":  o.MaxTokens,
		"system":      o.System,
		"messages":    []map[string]any{{"role": "user", "content": o.User + "\n\nAnswer by calling the tool " + o.ToolName + " exactly once."}},
		"tools":       []map[string]any{{"name": o.ToolName, "description": o.ToolDesc, "input_schema": o.Schema}},
		"tool_choice": map[string]any{"type": "auto"},
	}
	raw, status, err := doJSON(ctx, hc, strings.TrimRight(base, "/")+"/v1/messages", map[string]string{"x-api-key": key, "anthropic-version": anthropicVersion}, body)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, apiErrorText(raw, status)
	}
	var r struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
		Usage struct {
			In  int64 `json:"input_tokens"`
			Out int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return nil, perr("the reply is not valid JSON")
	}
	out := &Response{InputTokens: r.Usage.In, OutputTokens: r.Usage.Out}
	if r.StopReason == "refusal" {
		return out, perr("the model declined the request")
	}
	if r.StopReason == "max_tokens" {
		return out, perr("the answer was cut off (token limit); nothing was used")
	}
	for _, c := range r.Content {
		if c.Type == "tool_use" && c.Name == o.ToolName && len(c.Input) > 0 {
			out.JSON = c.Input
			return out, nil
		}
	}
	return out, perr("the model did not return the structured result")
}

func callOpenAI(ctx context.Context, hc *http.Client, base, key, model string, o *Outbound) (*Response, error) {
	mk := func(format map[string]any) map[string]any {
		return map[string]any{
			"model": model, "max_tokens": o.MaxTokens, "stream": false,
			"messages": []map[string]any{
				{"role": "system", "content": o.System},
				{"role": "user", "content": o.User + "\n\nReply with one JSON object only, matching this JSON schema: " + mustJSON(o.Schema)},
			},
			"response_format": format,
		}
	}
	hdr := map[string]string{}
	if key != "" {
		hdr["Authorization"] = "Bearer " + key
	}
	url := strings.TrimRight(base, "/") + "/chat/completions"
	raw, status, err := doJSON(ctx, hc, url, hdr, mk(map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": o.ToolName, "schema": o.Schema}}))
	if err != nil {
		return nil, err
	}
	if (status == http.StatusBadRequest || status == http.StatusUnprocessableEntity) && mentionsSchemaSupport(raw) { // server without json_schema support
		raw, status, err = doJSON(ctx, hc, url, hdr, mk(map[string]any{"type": "json_object"}))
		if err != nil {
			return nil, err
		}
	}
	if status != http.StatusOK {
		return nil, apiErrorText(raw, status)
	}
	var r struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			In  int64 `json:"prompt_tokens"`
			Out int64 `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &r) != nil || len(r.Choices) == 0 {
		return nil, perr("the reply is not a chat completion")
	}
	out := &Response{InputTokens: r.Usage.In, OutputTokens: r.Usage.Out}
	if r.Choices[0].FinishReason == "length" {
		return out, perr("the answer was cut off (token limit); nothing was used")
	}
	text := contentText(r.Choices[0].Message.Content)
	j, ok := extractJSONObject(text)
	if !ok {
		return out, perr("the model did not return a JSON object")
	}
	out.JSON = j
	return out, nil
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// extractJSONObject finds the first balanced top-level JSON object in text (models wrap JSON in
// prose or code fences). The result is validated strictly later.
func extractJSONObject(text string) ([]byte, bool) {
	start := strings.IndexByte(text, '{')
	if start < 0 {
		return nil, false
	}
	depth, inStr, esc := 0, false, false
	for i := start; i < len(text); i++ {
		c := text[i]
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return []byte(text[start : i+1]), true
			}
		}
	}
	return nil, false
}

// mentionsSchemaSupport is true when an error body complains about response_format / json_schema, the
// only case where a second request with json_object is worth sending (and costs another call).
func mentionsSchemaSupport(raw []byte) bool {
	l := strings.ToLower(string(raw))
	return strings.Contains(l, "schema") || strings.Contains(l, "response_format")
}

// contentText reads message.content, which is a string, null or a list of text parts.
func contentText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var b strings.Builder
		for _, p := range c {
			if m, ok := p.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					b.WriteString(t)
				}
			}
		}
		return b.String()
	}
	return ""
}
