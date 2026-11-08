package access

import (
	"errors"
	"maps"
	"sync"
)

/*
	bulk.go

	Additive helpers for bulk editing the IP lists of an access rule (used by
	the blocklist importer in mod/access/blocklistimport). The single entry
	AddIPToBlackList / AddIPToWhiteList copy the whole map and rewrite the
	config file on every call, which is quadratic for hundreds of thousands of
	entries. BulkEditIPList does one copy, one swap and one save.
*/

// IPListKind selects the IP blacklist or the IP whitelist of an access rule
type IPListKind int

const (
	IPListBlack IPListKind = iota
	IPListWhite
)

// bulkMu serialises bulk edits against each other
var bulkMu sync.Mutex

func (s *AccessRule) ipListMap(kind IPListKind) (map[string]string, error) {
	switch kind {
	case IPListBlack:
		if s.BlackListIP == nil {
			return map[string]string{}, nil
		}
		return *s.BlackListIP, nil
	case IPListWhite:
		if s.WhiteListIP == nil {
			return map[string]string{}, nil
		}
		return *s.WhiteListIP, nil
	}
	return nil, errors.New("unknown ip list kind")
}

// IPListSize returns the number of entries in the IP list
func (s *AccessRule) IPListSize(kind IPListKind) int {
	m, _ := s.ipListMap(kind)
	return len(m)
}

// IPListHas reports whether the exact key is an entry of the IP list
func (s *AccessRule) IPListHas(kind IPListKind, key string) bool {
	m, _ := s.ipListMap(kind)
	_, ok := m[key]
	return ok
}

// IPListSnapshot returns a copy of the IP list (entry -> comment)
func (s *AccessRule) IPListSnapshot(kind IPListKind) map[string]string {
	m, _ := s.ipListMap(kind)
	return maps.Clone(m)
}

// BulkEditIPList runs edit on a private copy of the list and publishes the
// result atomically with a single config file write. If edit returns an
// error nothing is changed or saved. If saving fails the
// previous list is restored and the error returned.
func (s *AccessRule) BulkEditIPList(kind IPListKind, edit func(m map[string]string) error) error {
	bulkMu.Lock()
	defer bulkMu.Unlock()
	cur, err := s.ipListMap(kind)
	if err != nil {
		return err
	}
	next := maps.Clone(cur)
	if next == nil {
		next = map[string]string{}
	}
	if err := edit(next); err != nil {
		return err
	}

	var old *map[string]string
	if kind == IPListBlack {
		old = s.BlackListIP
		s.BlackListIP = &next
	} else {
		old = s.WhiteListIP
		s.WhiteListIP = &next
	}
	if err := s.SaveChanges(); err != nil {
		if kind == IPListBlack {
			s.BlackListIP = old
		} else {
			s.WhiteListIP = old
		}
		return err
	}
	return nil
}
