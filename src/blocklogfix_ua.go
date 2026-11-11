package main

import (
	"errors"
	"fmt"
	"strings"

	"imuslab.com/zoraxy/mod/blocklog"
	"imuslab.com/zoraxy/mod/botrules"
	"imuslab.com/zoraxy/mod/dynamicproxy"
)

/*
	Fix "bot-ua-allow" of the Blocked drawer: let requests whose User-Agent contains a pattern skip the bot
	rules on THIS site only. The pattern is stored on the site (ProxyEndpoint.BotAllowUA) through the same
	write path as the other networking settings (applyNetworkingChange), so History, the site editor and the
	config file see it like any other edit. The drawer prefills the product token of the blocked client
	("curl/" for "curl/8.18.0") and lets the admin edit it; every value goes through botrules.NormalizeAllowUA.
*/

const botUASpoofWarning = "A User-Agent is trivially spoofable: anyone can send this text. This is a convenience for a known client, not security."

func botUAAllowFix(e blocklog.Entry, ep *dynamicproxy.ProxyEndpoint, site, pattern string) *fixCandidate {
	if ep.BotPolicy == "off" {
		return nil // nothing is judged on this site any more
	}
	id := botDecisionOf(e)
	if id == "fake-bot" || id == "empty-ua" || e.UA == "" {
		return nil // a spoofed trusted bot or no User-Agent at all: a User-Agent pattern is no answer
	}
	def, derr := botrules.AllowUAToken(e.UA)
	if derr != nil {
		return nil
	}
	edited := strings.TrimSpace(pattern) != ""
	value := def
	if edited {
		value = strings.TrimSpace(pattern)
	}
	in := &fixInput{Name: "pattern", Label: "User-Agent contains", Value: value,
		Help: "Lower case, 4 to 64 characters. Only the product name, for example curl/, never a version or a browser token."}
	c := &fixCandidate{fixOption: fixOption{
		ID: "bot-ua-allow", Scope: "site", Risk: "medium", Site: site, Warning: botUASpoofWarning, Input: in,
	}}
	norm, err := botrules.NormalizeAllowUA(value)
	if err == nil && !strings.Contains(strings.ToLower(e.UA), norm) {
		err = errors.New("the pattern must be part of the User-Agent of this request, otherwise it would not fix this block")
	}
	if err == nil {
		for _, have := range ep.BotAllowUA {
			if have == norm {
				return nil // already on the list
			}
		}
		if !edited && botrules.AllowedUA(ep.BotAllowUA, e.UA) {
			return nil // an entry of the list already covers this client
		}
		if len(ep.BotAllowUA) >= botrules.MaxAllowUAs {
			err = fmt.Errorf("this site already has %d allowed User-Agents (the limit); remove one in the site settings first", botrules.MaxAllowUAs)
		}
	}
	if err != nil {
		in.Error = err.Error()
		c.Label = "Allow a User-Agent on " + site
		c.Preview = ""
		c.Changes = []fixChange{}
		c.apply = func() (func() error, error) { return nil, err }
		return c
	}
	in.Value = norm
	prev := append([]string(nil), ep.BotAllowUA...)
	before := "(none)"
	if len(prev) > 0 {
		before = strings.Join(prev, ", ")
	}
	c.Label = fmt.Sprintf("Allow the User-Agent %q on %s", norm, site)
	c.Preview = fmt.Sprintf("After this: requests whose User-Agent contains \"%s\" skip the bot rules on %s only. Other sites unchanged.", norm, site)
	c.Changes = []fixChange{{What: "Allowed User-Agents of " + site, Before: before, After: strings.Join(append(append([]string(nil), prev...), norm), ", ")}}
	c.apply = func() (func() error, error) {
		if err := mutateBotAllowUA(site, func(list []string) ([]string, error) {
			for _, h := range list {
				if h == norm {
					return nil, errors.New("this User-Agent is on the list already")
				}
			}
			if len(list) >= botrules.MaxAllowUAs {
				return nil, fmt.Errorf("too many allowed User-Agents (max %d)", botrules.MaxAllowUAs)
			}
			return append(list, norm), nil
		}); err != nil {
			return nil, err
		}
		return func() error {
			return mutateBotAllowUA(site, func(list []string) ([]string, error) {
				out := make([]string, 0, len(list))
				found := false
				for _, h := range list {
					if h == norm {
						found = true
						continue
					}
					out = append(out, h)
				}
				if !found {
					return nil, errors.New("the allowed User-Agents of this site were changed after the fix; use the change history to restore an older version")
				}
				if len(out) == 0 {
					return nil, nil // "no list at all" as it was, not an empty one
				}
				return out, nil
			})
		}, nil
	}
	return c
}

// mutateBotAllowUA rewrites the allow list of one site through the normal networking write path
func mutateBotAllowUA(site string, f func(list []string) ([]string, error)) error {
	return applyNetworkingChange(site, func(x *dynamicproxy.ProxyEndpoint) error {
		out, err := f(append([]string(nil), x.BotAllowUA...))
		if err != nil {
			return err
		}
		x.BotAllowUA = out
		return nil
	})
}

// botUAAllowNote says why no User-Agent fix is offered for a bot block that looks like it could have one
func botUAAllowNote(e blocklog.Entry) string {
	if e.Reason != blocklog.ReasonBot || e.UA == "" {
		return ""
	}
	if id := botDecisionOf(e); id == "fake-bot" || id == "empty-ua" {
		return ""
	}
	if _, err := botrules.AllowUAToken(e.UA); err != nil && strings.Contains(strings.ToLower(e.UA), "mozilla/") {
		return "No User-Agent fix is offered: this client sends a browser-style User-Agent (Mozilla/...), and a pattern for it would allow every browser-like bot."
	}
	return ""
}
