package waf

/*
	respmatch.go

	A small Aho-Corasick automaton used as the prefilter of the response
	signatures. One pass over the inspection window finds where every signature
	anchor (a literal that must be part of any match) occurs, at a cost that does
	not depend on the number of signatures. The regular expressions then only run
	on the few hundred bytes around an anchor (see ResponseGuard.scan), which
	keeps the cost of clean pages low and bounds the cost of hostile ones.
*/

const (
	anchorSpacing = 512 // minimum distance between two recorded occurrences of the same anchor
	anchorMax     = 16  // occurrences recorded per anchor
)

type acMatcher struct {
	next   []int32    // state*256 + byte -> state*256 (premultiplied: no shift in the hot loop)
	out    [][]uint16 // literals that end in a state (including via suffix links)
	lens   []int
	nlits  int
	states int

	firstAccept int32 // premultiplied: states >= firstAccept have output
}

func buildAC(lits [][]byte) *acMatcher {
	type node struct {
		child [256]int32
		fail  int32
		out   []uint16
	}
	nodes := []node{{}}
	for i, l := range lits {
		cur := int32(0)
		for _, c := range l {
			if nodes[cur].child[c] == 0 {
				nodes = append(nodes, node{})
				nodes[cur].child[c] = int32(len(nodes) - 1)
			}
			cur = nodes[cur].child[c]
		}
		nodes[cur].out = append(nodes[cur].out, uint16(i))
	}
	if len(nodes) > 0xffff {
		panic("response signature anchors need too many automaton states")
	}
	// breadth first: failure links and complete transition table
	var queue []int32
	for c := 0; c < 256; c++ {
		if ch := nodes[0].child[c]; ch != 0 {
			queue = append(queue, ch)
		}
	}
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		nodes[u].out = append(nodes[u].out, nodes[nodes[u].fail].out...)
		for c := 0; c < 256; c++ {
			v := nodes[u].child[c]
			f := nodes[nodes[u].fail].child[c]
			if v == 0 {
				nodes[u].child[c] = f
				continue
			}
			nodes[v].fail = f
			queue = append(queue, v)
		}
	}
	// Renumber so that every state with output comes after all the others: the hot loop then only compares
	// the state number instead of loading the output list of every state.
	perm := make([]int, len(nodes)) // old -> new
	n := 0
	for i := range nodes {
		if len(nodes[i].out) == 0 {
			perm[i] = n
			n++
		}
	}
	first := n
	for i := range nodes {
		if len(nodes[i].out) > 0 {
			perm[i] = n
			n++
		}
	}
	m := &acMatcher{next: make([]int32, len(nodes)*256), out: make([][]uint16, len(nodes)), nlits: len(lits), states: len(nodes), firstAccept: int32(first) * 256}
	for i := range nodes {
		for c := 0; c < 256; c++ {
			m.next[perm[i]*256+c] = int32(perm[nodes[i].child[c]]) * 256
		}
		if len(nodes[i].out) > 0 {
			m.out[perm[i]] = nodes[i].out
		}
	}
	// ASCII case folding: an upper case letter takes the transition of its lower case form
	for i := range nodes {
		for c := 'A'; c <= 'Z'; c++ {
			m.next[i*256+int(c)] = m.next[i*256+int(c)+32]
		}
	}
	m.lens = make([]int, len(lits))
	for i, l := range lits {
		m.lens[i] = len(l)
	}
	return m
}

// anchorHits holds, for every literal, the start offsets of its (spaced) occurrences
type anchorHits [][]int32

// find runs the automaton over data. at most anchorMax occurrences per literal are kept, at least
// anchorSpacing bytes apart, so a page full of the same keyword cannot make the scan expensive.
func (m *acMatcher) find(data []byte) anchorHits {
	hits := make(anchorHits, m.nlits)
	var state int32
	next, out, first := m.next, m.out, m.firstAccept
	for i, c := range data {
		state = next[int(state)+int(c)]
		if state >= first {
			for _, id := range out[state>>8] {
				h := hits[id]
				start := int32(i + 1 - m.lens[id])
				if len(h) >= anchorMax || (len(h) > 0 && start-h[len(h)-1] < anchorSpacing) {
					continue
				}
				hits[id] = append(h, start)
			}
		}
	}
	return hits
}
