package main

import (
	"strconv"
	"strings"
	"time"

	"imuslab.com/zoraxy/mod/aiassist"
	"imuslab.com/zoraxy/mod/auth"
	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
	"imuslab.com/zoraxy/mod/posture"
)

/*
	aiassist_glue.go

	Connects the optional AI assistant (mod/aiassist) to the application. The assistant is off by
	default; creating the service starts nothing. See DEVELOPMENT.md, "AI assistant".
*/

var aiService *aiassist.Service

// RegisterAIAPIs registers /api/ai/* (admin session and CSRF protection come with the router).
func RegisterAIAPIs(authRouter *auth.RouterDef) {
	wireAIRules() // proposals are judged by the rules engine validator (aiassist_rules.go)
	if aiService == nil {
		aiService = aiassist.New(aiassist.Deps{
			ConfDir: CONF_FOLDER,
			Audit: func(event, detail string) {
				if authAgent != nil {
					authAgent.Audit("ai-assistant", event, "", "", detail)
				}
			},
			Events:  aiEvents{},
			Traffic: aiTraffic{},
			// The audit feature appears once the assistant is enabled; it only reads posture results.
			Posture: aiPosture{overview: func() posture.Overview { return getPostureEngine().Overview(false) }},
		})
	}
	aiService.RegisterHandlers(authRouter)
}

type aiEvents struct{}

func (aiEvents) WAFEvent(txid string) (*waf.Event, bool) {
	if txid == "" {
		return nil, false
	}
	for _, e := range waf.Default.QueryEvents(waf.EventFilter{Limit: 5000}) {
		if e.TransactionID == txid {
			ev := e
			return &ev, true
		}
	}
	return nil, false
}

func (aiEvents) BlockEntry(seq uint64) (*blocklog.Entry, bool) {
	if blockLog == nil || seq == 0 {
		return nil, false
	}
	res := blockLog.List(blocklog.Filter{}, seq+1, 1)
	if len(res.Items) == 1 && res.Items[0].Seq == seq {
		e := res.Items[0]
		return &e, true
	}
	return nil, false
}

type aiTraffic struct{}

// Traffic builds counts only. Request statistics are kept per calendar day, so the request side
// covers today so far; the blocked-request log and the WAF events cover the requested window.
func (aiTraffic) Traffic(since time.Time, hours int) aiassist.RawTraffic {
	t := aiassist.RawTraffic{WindowHours: hours}
	if statisticCollector != nil {
		d := statisticCollector.GetExportSummary()
		t.Requests, t.Errors, t.Blocked = d.TotalRequest, d.ErrorRequest, d.BlockedRequest
		t.StatusMix, t.Countries, t.UserAgents, t.TopPaths, t.Hosts = d.StatusCodes, d.RequestOrigin, d.UserAgent, d.RequestURL, d.Downstreams
		t.TopIPs = d.RequestClientIp
	}
	if blockLog != nil {
		s := blockLog.Summarize(blocklog.Filter{Since: since.Unix()}, time.Now())
		t.BlockReasons = map[string]int{}
		for _, c := range s.Reasons {
			t.BlockReasons[c.Key] = c.N
			if c.Key == blocklog.ReasonAuth {
				t.AuthFailures = int64(c.N)
			}
		}
	}
	sum := waf.Default.Summary(since, 20)
	t.WAFRules = map[string]int{}
	for _, c := range sum.TopRules {
		label := c.Key
		if id, err := strconv.Atoi(c.Key); err == nil {
			if ref, ok := waf.LookupRule(id); ok {
				label = c.Key + " " + ref.Message
			}
		}
		t.WAFRules[label] = c.Count
	}
	return t
}

// aiPosture feeds the AI configuration audit from the security posture checks. It only reads the
// cached check results; it never previews or applies a fix.
type aiPosture struct {
	overview func() posture.Overview
}

// Items implements aiassist.PostureSource. Checks that do not apply are skipped; checks whose
// state could not be determined are reported as warnings so they are never read as passing.
func (p aiPosture) Items() []aiassist.PostureItem {
	if p.overview == nil {
		return nil
	}
	var out []aiassist.PostureItem
	for _, c := range p.overview().Checks {
		status := ""
		switch c.Status {
		case posture.StatusOK:
			status = "pass"
		case posture.StatusWarn, posture.StatusUnknown:
			status = "warn"
		case posture.StatusFail:
			status = "fail"
		default:
			continue
		}
		detail := c.Why
		if len(c.Evidence) > 0 {
			detail = strings.Join(c.Evidence, "; ")
		}
		out = append(out, aiassist.PostureItem{ID: c.ID, Title: c.Title, Status: status, Severity: c.Severity, Detail: detail})
	}
	return out
}
