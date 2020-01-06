package xorfilter

import (
	"errors"
	"math"
)

// Xor8TwoSegment offers a ~0.3% false-positive probability,
// Version of Xor8 that collocates the first two hits
// credit: Sokolov Yura (@funny-falcon)
type experimentalXor8TwoSegment struct {
	Seed         uint64
	BlockLength  uint32
	Size         uint32
	Fingerprints []uint8
}

// Contains tell you whether the key is likely part of the set
// it is a proof-of concept and not recommended because
// there is no guarantee that it will work within a reasonably time.
func (filter *experimentalXor8TwoSegment) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := uint8(fingerprint(hash))
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.BlockLength)
	h1 := h0 ^ (reduce(r1, 63) + 1)
	h2 := reduce(r2, filter.BlockLength) + filter.BlockLength
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^
		filter.Fingerprints[h2])
}

func (filter *experimentalXor8TwoSegment) geth0h1h2(k uint64) hashes {
	hash := mixsplit(k, filter.Seed)
	answer := hashes{}
	answer.h = hash
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))

	answer.h0 = reduce(r0, filter.BlockLength)
	answer.h1 = answer.h0 ^ (reduce(r1, 63) + 1)
	answer.h2 = reduce(r2, filter.BlockLength)
	return answer
}

func (filter *experimentalXor8TwoSegment) geth0(hash uint64) uint32 {
	r0 := uint32(hash)
	return reduce(r0, filter.BlockLength)
}

func (filter *experimentalXor8TwoSegment) geth1(h0 uint32, hash uint64) uint32 {
	r1 := uint32(rotl64(hash, 21))
	return h0 ^ (reduce(r1, 63) + 1)
}

func (filter *experimentalXor8TwoSegment) geth2(hash uint64) uint32 {
	r2 := uint32(rotl64(hash, 42))
	return reduce(r2, filter.BlockLength)
}

// PopulateTwoSegment fills the filter with provided keys.
// The caller is responsible to ensure that there are no duplicate keys.
func experimentalPopulateTwoSegment(keys []uint64) (*experimentalXor8TwoSegment, error) {
	size := len(keys)
	capacity := 32 + uint32(math.Ceil(1.27*float64(size))) // it is not clear where 1.27 comes from
	filter := &experimentalXor8TwoSegment{}
	filter.Size = uint32(len(keys))
	filter.BlockLength = capacity / 2
	filter.BlockLength = (filter.BlockLength + 63) &^ 63 // round up to 64 bit blocks
	capacity = filter.BlockLength * 2
	filter.Fingerprints = make([]uint8, capacity, capacity)
	var rngcounter uint64 = 1
	filter.Seed = splitmix64(&rngcounter)

	Q0 := make([]keyindex, filter.BlockLength, filter.BlockLength)
	Q1 := make([]keyindex, filter.BlockLength, filter.BlockLength)
	stack := make([]keyindex, size, size)
	sets0 := make([]xorset, filter.BlockLength, filter.BlockLength)
	sets1 := make([]xorset, filter.BlockLength, filter.BlockLength)
	iterations := 0
	for true {
		iterations++
		if iterations > MaxIterations {
			return nil, errors.New("too many iterations, you probably have duplicate keys")
		}
		for i := 0; i < size; i++ {
			key := keys[i]
			hs := filter.geth0h1h2(key)
			sets0[hs.h0].xormask ^= hs.h
			sets0[hs.h0].count++
			sets0[hs.h1].xormask ^= hs.h
			sets0[hs.h1].count++
			sets1[hs.h2].xormask ^= hs.h
			sets1[hs.h2].count++
		}
		// scan for values with a count of one
		Q0size := 0
		Q1size := 0
		for i := uint32(0); i < filter.BlockLength; i++ {
			if sets0[i].count == 1 {
				Q0[Q0size].index = i
				Q0[Q0size].hash = sets0[i].xormask
				Q0size++
			}
		}

		for i := uint32(0); i < filter.BlockLength; i++ {
			if sets1[i].count == 1 {
				Q1[Q1size].index = i
				Q1[Q1size].hash = sets1[i].xormask
				Q1size++
			}
		}
		stacksize := 0
		for Q0size+Q1size > 0 {
			for Q0size > 0 {
				Q0size--
				keyindexvar := Q0[Q0size]
				index := keyindexvar.index
				if sets0[index].count == 0 {
					continue // not actually possible after the initial scan.
				}
				hash := keyindexvar.hash
				h0 := filter.geth0(hash)
				h1 := filter.geth1(h0, hash)
				h2 := filter.geth2(hash)
				stack[stacksize] = keyindexvar
				stacksize++
				sets0[h0].xormask ^= hash
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}
				sets0[h1].xormask ^= hash
				sets0[h1].count--
				if sets0[h1].count == 1 {
					Q0[Q0size].index = h1
					Q0[Q0size].hash = sets0[h1].xormask
					Q0size++
				}
				sets1[h2].xormask ^= hash
				sets1[h2].count--
				if sets1[h2].count == 1 {
					Q1[Q1size].index = h2
					Q1[Q1size].hash = sets1[h2].xormask
					Q1size++
				}
			}
			if Q1size > 0 {
				Q1size--
				keyindexvar := Q1[Q1size]
				index := keyindexvar.index
				if sets1[index].count == 0 {
					continue
				}
				sets1[index].count = 0
				hash := keyindexvar.hash
				h0 := filter.geth0(hash)
				h1 := filter.geth1(h0, hash)
				keyindexvar.index += filter.BlockLength

				stack[stacksize] = keyindexvar
				stacksize++
				sets0[h0].xormask ^= hash
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}
				sets0[h1].xormask ^= hash
				sets0[h1].count--
				if sets0[h1].count == 1 {
					Q0[Q0size].index = h1
					Q0[Q0size].hash = sets0[h1].xormask
					Q0size++
				}

			}
		}

		if stacksize == size {
			// success
			break
		}

		for i := range sets0 {
			sets0[i] = xorset{0, 0}
		}
		for i := range sets1 {
			sets1[i] = xorset{0, 0}
		}
		filter.Seed = splitmix64(&rngcounter)
	}

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint8(fingerprint(ki.hash))
		if ki.index < filter.BlockLength {
			h0 := filter.geth0(ki.hash)
			h1 := filter.geth1(h0, ki.hash)
			h2 := filter.geth2(ki.hash)
			val ^= filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2+filter.BlockLength]
		} else {
			h0 := filter.geth0(ki.hash)
			val ^= filter.Fingerprints[h0] ^ filter.Fingerprints[filter.geth1(h0, ki.hash)]
		}
		filter.Fingerprints[ki.index] = val
	}
	return filter, nil
}
