package access

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

/*
	ruleextra.go

	Optional, default-off additions to access rules:
	  - SortOrder                 manual ordering in the rule list (upstream #762)
	  - DuplicateAccessRule       copy a rule (upstream #762)
	  - DropOnBlock               close the TCP connection of blocked clients instead of
	                              answering with the 403 page (upstream #908)
	  - ChallengeCountryCode      countries that get the endpoint's CAPTCHA instead of being
	                              blocked (upstream #281)
*/

// extraMu guards ChallengeCountryCode of all rules (rarely written; a shared lock keeps AccessRule copy-safe)
var extraMu sync.RWMutex

// IsCountryChallenged reports whether the country of ipAddr is on the challenge list.
// Blacklisted clients never get here (a block always wins over a challenge).
func (s *AccessRule) IsCountryChallenged(ipAddr string) bool {
	m := s.challengeMap()
	if len(m) == 0 || ipAddr == "" {
		return false
	}
	cc, err := s.resolveCountry(ipAddr)
	if err != nil || cc == "" {
		return false
	}
	_, ok := m[strings.ToLower(cc)]
	return ok
}

func (s *AccessRule) challengeMap() map[string]string {
	extraMu.RLock()
	defer extraMu.RUnlock()
	if s.ChallengeCountryCode == nil {
		return nil
	}
	return *s.ChallengeCountryCode
}

// AddChallengeCountry adds a country code to the challenge list
func (s *AccessRule) AddChallengeCountry(code, comment string) error {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) != 2 {
		return errors.New("country code must be 2 letters")
	}
	for _, c := range code {
		if c < 'a' || c > 'z' {
			return errors.New("country code must be 2 letters")
		}
	}
	extraMu.Lock()
	if s.ChallengeCountryCode == nil {
		s.ChallengeCountryCode = &map[string]string{}
	}
	(*s.ChallengeCountryCode)[code] = comment
	extraMu.Unlock()
	return s.SaveChanges()
}

// RemoveChallengeCountry removes a country code from the challenge list
func (s *AccessRule) RemoveChallengeCountry(code string) error {
	extraMu.Lock()
	if s.ChallengeCountryCode != nil {
		delete(*s.ChallengeCountryCode, strings.ToLower(strings.TrimSpace(code)))
	}
	extraMu.Unlock()
	return s.SaveChanges()
}

// ListChallengeCountries returns the challenge list (code -> comment)
func (s *AccessRule) ListChallengeCountries() map[string]string {
	out := map[string]string{}
	for k, v := range s.challengeMap() {
		out[k] = v
	}
	return out
}

// SetDropOnBlock toggles closing blocked connections without a response
func (s *AccessRule) SetDropOnBlock(enabled bool) error {
	s.DropOnBlock = enabled
	return s.SaveChanges()
}

// DuplicateAccessRule copies a rule (all lists and options) under a new ID and name
func (c *Controller) DuplicateAccessRule(srcID, newName string) (*AccessRule, error) {
	src, err := c.GetAccessRuleByID(srcID)
	if err != nil {
		return nil, err
	}
	if src == nil {
		return nil, errors.New("source access rule not loaded")
	}
	if strings.TrimSpace(newName) == "" {
		newName = src.Name + " (copy)"
	}
	cp := &AccessRule{
		ID:                             uuid.New().String(),
		Name:                           newName,
		Desc:                           src.Desc,
		BlacklistEnabled:               src.BlacklistEnabled,
		WhitelistEnabled:               src.WhitelistEnabled,
		WhitelistAllowLocalAndLoopback: src.WhitelistAllowLocalAndLoopback,
		TrustProxyHeadersOnly:          src.TrustProxyHeadersOnly,
		DropOnBlock:                    src.DropOnBlock,
		SortOrder:                      src.SortOrder,
	}
	cp.WhiteListCountryCode = copyMapPtr(src.WhiteListCountryCode)
	cp.WhiteListIP = copyMapPtr(src.WhiteListIP)
	cp.BlackListContryCode = copyMapPtr(src.BlackListContryCode)
	cp.BlackListIP = copyMapPtr(src.BlackListIP)
	if cc := src.challengeMap(); len(cc) > 0 {
		m := map[string]string{}
		for k, v := range cc {
			m[k] = v
		}
		cp.ChallengeCountryCode = &m
	}
	if err := c.AddNewAccessRule(cp); err != nil {
		return nil, err
	}
	return cp, nil
}

func copyMapPtr(m *map[string]string) *map[string]string {
	out := map[string]string{}
	if m != nil {
		for k, v := range *m {
			out[k] = v
		}
	}
	return &out
}

// SetRuleOrder stores the manual order: ids[0] first. Unknown ids are rejected,
// rules not listed keep their relative order after the listed ones.
func (c *Controller) SetRuleOrder(ids []string) error {
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "default" || id == "" {
			continue //the default rule is always listed first
		}
		if seen[id] {
			return errors.New("duplicate id in order list")
		}
		seen[id] = true
		if !c.AccessRuleExists(id) {
			return errors.New("unknown access rule: " + id)
		}
	}
	pos := 1
	for _, id := range ids {
		if id == "default" || id == "" {
			continue
		}
		r, _ := c.GetAccessRuleByID(id)
		r.SortOrder = pos
		pos++
		if err := r.SaveChanges(); err != nil {
			return err
		}
	}
	return nil
}

// SortRules returns rules sorted by mode: "name", "manual" (default: SortOrder, then name) or "id".
// The default rule is always first.
func SortRules(rules []*AccessRule, mode string) []*AccessRule {
	out := make([]*AccessRule, 0, len(rules))
	for _, r := range rules {
		if r != nil {
			out = append(out, r)
		}
	}
	less := func(a, b *AccessRule) bool {
		switch mode {
		case "name":
		case "id":
			if a.ID != b.ID {
				return a.ID < b.ID
			}
		default:
			ao, bo := a.SortOrder, b.SortOrder
			if ao == 0 {
				ao = 1 << 30 //never ordered: after the manually ordered ones
			}
			if bo == 0 {
				bo = 1 << 30
			}
			if ao != bo {
				return ao < bo
			}
		}
		an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if an != bn {
			return an < bn
		}
		return a.ID < b.ID
	}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].ID == "default") != (out[j].ID == "default") {
			return out[i].ID == "default"
		}
		return less(out[i], out[j])
	})
	return out
}
