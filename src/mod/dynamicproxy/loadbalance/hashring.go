package loadbalance

import (
	"hash/fnv"
	"sort"
	"strconv"
)

/*
	Consistent hash ring with virtual nodes

	Clean-room implementation of the classic ketama-style ring (the technique
	is described in the original Karger et al. paper and is used by many
	proxies). Every upstream owns a number of points on a 64 bit ring in
	proportion to its weight. A key maps to the first point clockwise from its
	hash. Adding or removing one of N upstreams only remaps about 1/N of the keys.
*/

const ringVNodesPerWeight = 160
const ringMaxUnitWeight = 32 //Weights above this are scaled down to keep the ring small

type ringNode struct {
	hash uint64
	up   *Upstream
}

type hashRing struct {
	nodes []ringNode
	//Cache signature: the exact members and weights the ring was built from
	members []*Upstream
	weights []int
}

// mix64 is the splitmix64 finalizer, FNV alone has a weak avalanche on similar labels
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// hashString returns a stable (across runs and machines) 64 bit hash of s
func hashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return mix64(h.Sum64())
}

// buildRing creates a ring for the given upstreams. A weight of 0 (fallback group) counts as 1
func buildRing(ups []*Upstream) *hashRing {
	r := &hashRing{members: append([]*Upstream(nil), ups...), weights: make([]int, len(ups))}
	maxW := 1
	for i, u := range ups {
		w := u.Weight
		if w < 1 {
			w = 1
		}
		r.weights[i] = u.Weight
		if w > maxW {
			maxW = w
		}
	}
	scale := 1.0
	if maxW > ringMaxUnitWeight {
		scale = float64(ringMaxUnitWeight) / float64(maxW)
	}
	for _, u := range ups {
		w := u.Weight
		if w < 1 {
			w = 1
		}
		count := int(float64(ringVNodesPerWeight*w) * scale)
		if count < 8 {
			count = 8
		}
		for i := 0; i < count; i++ {
			//Nodes are named after the origin address, not the pointer, so the
			//placement survives a config reload or an upstream object replacement
			r.nodes = append(r.nodes, ringNode{hash: hashString(u.OriginIpOrDomain + "#" + strconv.Itoa(i)), up: u})
		}
	}
	sort.Slice(r.nodes, func(i, j int) bool { return r.nodes[i].hash < r.nodes[j].hash })
	return r
}

// sameMembers reports whether the ring was built from exactly these upstream objects and weights
func (r *hashRing) sameMembers(ups []*Upstream) bool {
	if r == nil || len(r.members) != len(ups) {
		return false
	}
	for i, u := range ups {
		if r.members[i] != u || r.weights[i] != u.Weight {
			return false
		}
	}
	return true
}

// pick returns the first upstream clockwise from key for which allowed returns true
func (r *hashRing) pick(key uint64, allowed func(*Upstream) bool) *Upstream {
	n := len(r.nodes)
	if n == 0 {
		return nil
	}
	start := sort.Search(n, func(i int) bool { return r.nodes[i].hash >= key })
	var rejected []*Upstream //Small, at most one entry per upstream
	for i := 0; i < n; i++ {
		u := r.nodes[(start+i)%n].up
		skip := false
		for _, x := range rejected {
			if x == u {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if allowed(u) {
			return u
		}
		rejected = append(rejected, u)
		if len(rejected) >= len(r.members) {
			return nil
		}
	}
	return nil
}
