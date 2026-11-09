package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/waf"
)

/*
	wafcentral.go

	Persistence and mutation of the central WAF policy and profiles.

	The state lives in <conf>/waf_central.json (not the sysdb) so that it is part
	of the conf backup zip and of cluster snapshots (allow-listed in
	mod/cluster/snapshot.go) and therefore replicates to followers. A missing
	file means "WAF globally off, no custom profiles", which is exactly the
	behaviour before the central WAF existed.
*/

type wafCentralFile struct {
	Policy   waf.Policy
	Profiles []waf.Profile
}

// wafCentralMu serialises every read-modify-write of the central state or of an
// endpoint's WAF setting, so concurrent API calls cannot lose each other's edits.
var wafCentralMu sync.Mutex

func loadWAFCentralState(file string) (*waf.State, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return waf.EmptyState(), nil
		}
		return waf.EmptyState(), err
	}
	f := wafCentralFile{Policy: waf.DefaultPolicy()}
	if err := json.Unmarshal(raw, &f); err != nil {
		return waf.EmptyState(), err
	}
	st, err := waf.NewState(f.Policy, f.Profiles)
	if err != nil {
		return waf.EmptyState(), err
	}
	return st, nil
}

func saveWAFCentralState(file string, st *waf.State) error {
	f := wafCentralFile{Policy: st.Policy, Profiles: st.UserProfiles()}
	js, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return err
	}
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, js, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// initWAFCentral loads the stored state into the router. Call before endpoints are loaded.
func initWAFCentral() {
	st, err := loadWAFCentralState(CONF_WAF_CENTRAL)
	if err != nil {
		SystemWideLogger.PrintAndLog("waf", "Unable to load the central WAF configuration, WAF policy is off until it is fixed: "+err.Error(), nil)
	}
	dynamicProxyRouter.SetWAFState(st)
}

// mutateWAFCentral applies a change to the policy / profile list. The new state
// must validate and compile for every endpoint before anything changes.
func mutateWAFCentral(fn func(p *waf.Policy, profiles *[]waf.Profile) error) error {
	wafCentralMu.Lock()
	defer wafCentralMu.Unlock()
	return mutateWAFCentralLocked(fn)
}

func mutateWAFCentralLocked(fn func(p *waf.Policy, profiles *[]waf.Profile) error) error {
	old := dynamicProxyRouter.WAFState()
	pol := old.Policy
	pol.ExcludedRuleIDs = append([]string(nil), pol.ExcludedRuleIDs...)
	pol.PathExclusions = append([]waf.PathExclusion(nil), pol.PathExclusions...)
	pol.TargetExclusions = append([]waf.TargetExclusion(nil), pol.TargetExclusions...)
	pol.TrustedPaths = append([]waf.TrustedPath(nil), pol.TrustedPaths...)
	pol.AllowedIPs = append([]string(nil), pol.AllowedIPs...)
	profiles := old.UserProfiles()
	if err := fn(&pol, &profiles); err != nil {
		return err
	}
	st, err := waf.NewState(pol, profiles)
	if err != nil {
		return err
	}
	if err := dynamicProxyRouter.ApplyWAFState(st); err != nil {
		return err
	}
	if err := saveWAFCentralState(CONF_WAF_CENTRAL, st); err != nil {
		// Keep memory and disk consistent
		dynamicProxyRouter.ApplyWAFState(old)
		return fmt.Errorf("unable to save the WAF configuration: %w", err)
	}
	return nil
}

// profileUsage maps lower case profile name to the endpoints that use it
func profileUsage() map[string][]string {
	use := map[string][]string{}
	for _, c := range dynamicProxyRouter.WAFCoverage() {
		if c.Source == waf.SourceProfile {
			k := strings.ToLower(c.Profile)
			use[k] = append(use[k], c.Endpoint)
		}
	}
	return use
}

func deleteWAFProfile(name string) error {
	return mutateWAFCentral(func(p *waf.Policy, profiles *[]waf.Profile) error {
		if cur, ok := dynamicProxyRouter.WAFState().Profile(name); ok && cur.BuiltIn {
			return errors.New("built-in profiles cannot be deleted")
		}
		if eps := profileUsage()[strings.ToLower(strings.TrimSpace(name))]; len(eps) > 0 {
			return fmt.Errorf("profile is in use by %d endpoint(s): %s", len(eps), strings.Join(eps, ", "))
		}
		var out []waf.Profile
		found := false
		for _, pr := range *profiles {
			if strings.EqualFold(pr.Name, strings.TrimSpace(name)) {
				found = true
				continue
			}
			out = append(out, pr)
		}
		if !found {
			return errors.New("profile not found")
		}
		*profiles = out
		return nil
	})
}

// applyWAFEndpoint changes the WAF settings of one endpoint ("/" = default site)
// at runtime and persists them. Compile errors reject the change.
func applyWAFEndpoint(name string, mutate func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error) error {
	wafCentralMu.Lock()
	defer wafCentralMu.Unlock()
	return applyWAFEndpointLocked(name, mutate)
}

func applyWAFEndpointLocked(name string, mutate func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error) error {
	isRoot := name == "/"
	var target *dynamicproxy.ProxyEndpoint
	if isRoot {
		target = dynamicProxyRouter.Root
		if target == nil {
			return errors.New("default site is not configured")
		}
	} else {
		var err error
		target, err = dynamicProxyRouter.LoadProxy(name)
		if err != nil {
			return err
		}
	}
	updated := dynamicproxy.CopyEndpoint(target)
	if updated == nil {
		return errors.New("unable to copy the endpoint")
	}
	if err := mutate(updated, dynamicProxyRouter.WAFState()); err != nil {
		return err
	}
	if err := dynamicProxyRouter.WAFState().ValidateSetting(updated.WAFSetting()); err != nil {
		return err
	}
	ready, err := dynamicProxyRouter.PrepareProxyRoute(updated)
	if err != nil {
		return err
	}
	if isRoot {
		if err := dynamicProxyRouter.SetProxyRouteAsRoot(ready); err != nil {
			return err
		}
	} else {
		target.Remove()
		loadBalancer.ResetSessions()
		dynamicProxyRouter.AddProxyRouteToRuntime(ready)
	}
	return SaveReverseProxyConfig(updated)
}

// addUnique appends v unless present
func addUnique(list []string, v string) []string {
	for _, x := range list {
		if strings.TrimSpace(x) == v {
			return list
		}
	}
	return append(list, v)
}

func addPathExclusion(list []waf.PathExclusion, pe waf.PathExclusion) []waf.PathExclusion {
	for i, x := range list {
		if x.Path == pe.Path && x.Exact == pe.Exact {
			list[i].RuleIDs = addUnique(append([]string(nil), x.RuleIDs...), pe.RuleIDs[0])
			return list
		}
	}
	return append(list, pe)
}

// addExclusion adds rule exclusion to the policy (scope global) or an endpoint.
func addWAFExclusion(scope, endpoint, ruleID, path string, exact bool) error {
	ruleID = strings.TrimSpace(ruleID)
	probe := waf.Config{Mode: waf.ModeDetectionOnly, ExcludedRuleIDs: []string{ruleID}}
	if err := probe.Validate(); err != nil {
		return err
	}
	if scope == "global" {
		return mutateWAFCentral(func(p *waf.Policy, _ *[]waf.Profile) error {
			if path == "" {
				p.ExcludedRuleIDs = addUnique(p.ExcludedRuleIDs, ruleID)
			} else {
				p.PathExclusions = addPathExclusion(p.PathExclusions, waf.PathExclusion{Path: path, Exact: exact, RuleIDs: []string{ruleID}})
			}
			return nil
		})
	}
	if endpoint == "" {
		return errors.New("Target proxy rule not defined")
	}
	return applyWAFEndpoint(endpoint, func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error {
		switch ep.WAFSetting().EffectiveSource() {
		case waf.SourceOff:
			return errors.New("WAF is switched off for this endpoint")
		case waf.SourceCustom:
			var cfg waf.Config
			if ep.WAF != nil {
				cfg = *ep.WAF
				cfg.ExcludedRuleIDs = append([]string(nil), cfg.ExcludedRuleIDs...)
				cfg.PathExclusions = append([]waf.PathExclusion(nil), cfg.PathExclusions...)
			}
			if path == "" {
				cfg.ExcludedRuleIDs = addUnique(cfg.ExcludedRuleIDs, ruleID)
			} else {
				cfg.PathExclusions = addPathExclusion(cfg.PathExclusions, waf.PathExclusion{Path: path, Exact: exact, RuleIDs: []string{ruleID}})
			}
			ep.WAF = &cfg
			ep.WAFSource = waf.SourceCustom
		default:
			x := waf.Overrides{}
			if ep.WAFExtra != nil {
				x = *ep.WAFExtra
				x.ExcludedRuleIDs = append([]string(nil), x.ExcludedRuleIDs...)
				x.PathExclusions = append([]waf.PathExclusion(nil), x.PathExclusions...)
			}
			if path == "" {
				x.ExcludedRuleIDs = addUnique(x.ExcludedRuleIDs, ruleID)
			} else {
				x.PathExclusions = addPathExclusion(x.PathExclusions, waf.PathExclusion{Path: path, Exact: exact, RuleIDs: []string{ruleID}})
			}
			ep.WAFExtra = &x
		}
		return nil
	})
}

// setWAFEndpointSource changes where an endpoint takes its WAF from.
// extra == nil keeps the existing additive overrides.
func setWAFEndpointSource(name, source, profile string, extra *waf.Overrides, setExtra bool) error {
	source = strings.ToLower(strings.TrimSpace(source))
	return applyWAFEndpoint(name, func(ep *dynamicproxy.ProxyEndpoint, st *waf.State) error {
		if source == waf.SourceCustom && ep.WAF == nil {
			// Starting a custom config: begin from the config the endpoint effectively has now
			res := st.Resolve(ep.WAFSetting())
			if res.Config != nil {
				c := *res.Config
				ep.WAF = &c
			} else {
				ep.WAF = &waf.Config{Mode: waf.ModeDetectionOnly}
			}
		}
		ep.WAFSource = source
		ep.WAFProfile = ""
		if source == waf.SourceProfile {
			ep.WAFProfile = profile
		}
		if setExtra {
			ep.WAFExtra = extra
		}
		return nil
	})
}

var (
	errBuiltinProfile = errors.New("built-in profiles are read-only: clone it to make an editable copy")
	errProfileExists  = errors.New("a profile with that name already exists")
	errProfileMissing = errors.New("profile not found")
)
