package redirection

import (
	"errors"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

/*
	advanced.go

	Optional "advanced regex" engine for redirect rules (upstream #689).

	Go's regexp package (RE2) has guaranteed linear matching but no lookahead / lookbehind /
	backreferences. When RuleTable.AdvancedRegex is on, rule patterns are matched with
	github.com/dlclark/regexp2 (MIT), a backtracking engine with those features. Because a
	backtracking engine can be driven into catastrophic runtime (ReDoS) by crafted request
	URLs, every match has a hard timeout (AdvancedRegexTimeout) and the input is capped; a
	timeout counts as "no match" and is logged. The default engine is unchanged.
*/

const (
	AdvancedRegexTimeout   = 50 * time.Millisecond
	MaxAdvancedPatternLen  = 500
	MaxAdvancedInputLen    = 4096
	maxCompiledAdvancedRes = 1024
)

var advancedCache sync.Map //pattern -> *regexp2.Regexp (or error)
var advancedCacheSize int
var advancedCacheMu sync.Mutex

// CompileAdvancedRegex compiles a pattern for the backtracking engine, with the match timeout set
func CompileAdvancedRegex(pattern string) (*regexp2.Regexp, error) {
	if len(pattern) > MaxAdvancedPatternLen {
		return nil, errors.New("pattern too long")
	}
	if v, ok := advancedCache.Load(pattern); ok {
		if re, ok := v.(*regexp2.Regexp); ok {
			return re, nil
		}
		return nil, v.(error)
	}
	re, err := regexp2.Compile(pattern, regexp2.None)
	var store interface{} = err
	if err == nil {
		re.MatchTimeout = AdvancedRegexTimeout
		store = re
	}
	advancedCacheMu.Lock()
	if advancedCacheSize >= maxCompiledAdvancedRes {
		advancedCache.Range(func(k, _ interface{}) bool { advancedCache.Delete(k); return true })
		advancedCacheSize = 0
	}
	advancedCacheSize++
	advancedCacheMu.Unlock()
	advancedCache.Store(pattern, store)
	return re, err
}

// ValidateAdvancedRegex reports whether the pattern compiles in the advanced engine
func ValidateAdvancedRegex(pattern string) error {
	_, err := CompileAdvancedRegex(pattern)
	return err
}

// advancedMatch matches with the timeout. A timeout returns (false, ErrAdvancedRegexTimeout).
func advancedMatch(pattern, input string) (bool, error) {
	re, err := CompileAdvancedRegex(pattern)
	if err != nil {
		return false, err
	}
	if len(input) > MaxAdvancedInputLen {
		input = input[:MaxAdvancedInputLen]
	}
	ok, err := re.MatchString(input)
	if err != nil {
		return false, ErrAdvancedRegexTimeout
	}
	return ok, nil
}

// ErrAdvancedRegexTimeout is returned when a pattern exceeded the match time budget
var ErrAdvancedRegexTimeout = errors.New("advanced regex match timed out")
