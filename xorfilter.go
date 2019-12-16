package xorfilter

import (
	"math"
)

// Xor8 offers a 0.3% false-positive probability
type Xor8 struct {
	seed         uint64
	blockLength  uint32
	fingerprints []uint8
}

type xorset struct {
	xormask uint64
	count   uint32
}

type hashes struct {
	h  uint64
	h0 uint32
	h1 uint32
	h2 uint32
}

type keyindex struct {
	hash  uint64
	index uint32
}

func murmur64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// returns random number, modifies the seed
func splitmix64(seed *uint64) uint64 {
	*seed = *seed + 0x9E3779B97F4A7C15
	z := *seed
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func mixsplit(key, seed uint64) uint64 {
	return murmur64(key + seed)
}

func rotl64(n uint64, c int) uint64 {
	return (n << (c & 63)) | (n >> ((-c) & 63))
}

func reduce(hash, n uint32) uint32 {
	// http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
	return uint32((uint64(hash) * uint64(n)) >> 32)
}

func fingerprint(hash uint64) uint64 {
	return hash ^ (hash >> 32)
}

// Contains tell you whether the key is likely part of the set
func (filter *Xor8) Contains(key uint64) bool {
	hash := mixsplit(key, filter.seed)
	f := uint8(fingerprint(hash))
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	h0 := reduce(r0, filter.blockLength)
	h1 := reduce(r1, filter.blockLength) + filter.blockLength
	h2 := reduce(r2, filter.blockLength) + 2*filter.blockLength
	return f == (filter.fingerprints[h0] ^ filter.fingerprints[h1] ^
		filter.fingerprints[h2])
}

func (filter *Xor8) geth0h1h2(k uint64) hashes {
	hash := mixsplit(k, filter.seed)
	answer := hashes{}
	answer.h = hash
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))

	answer.h0 = reduce(r0, filter.blockLength)
	answer.h1 = reduce(r1, filter.blockLength)
	answer.h2 = reduce(r2, filter.blockLength)
	return answer
}

func (filter *Xor8) geth0(hash uint64) uint32 {
	r0 := uint32(hash)
	return reduce(r0, filter.blockLength)
}

func (filter *Xor8) geth1(hash uint64) uint32 {
	r1 := uint32(rotl64(hash, 21))
	return reduce(r1, filter.blockLength)
}

func (filter *Xor8) geth2(hash uint64) uint32 {
	r2 := uint32(rotl64(hash, 42))
	return reduce(r2, filter.blockLength)
}

// Populate fills the filter with provided keys.
func Populate(keys []uint64) *Xor8 {
	size := len(keys)
	capacity := 32 + uint32(math.Ceil(1.23*float64(size)))
	capacity = capacity / 3 * 3 // round it down to a multiple of 3
	filter := &Xor8{}
	filter.blockLength = capacity / 3
	filter.fingerprints = make([]uint8, capacity, capacity)
	var rngcounter uint64 = 1
	filter.seed = splitmix64(&rngcounter)

	Q0 := make([]keyindex, filter.blockLength, filter.blockLength)
	Q1 := make([]keyindex, filter.blockLength, filter.blockLength)
	Q2 := make([]keyindex, filter.blockLength, filter.blockLength)
	stack := make([]keyindex, size, size)
	sets0 := make([]xorset, filter.blockLength, filter.blockLength)
	sets1 := make([]xorset, filter.blockLength, filter.blockLength)
	sets2 := make([]xorset, filter.blockLength, filter.blockLength)
	for true {
		for i := 0; i < size; i++ {
			key := keys[i]
			hs := filter.geth0h1h2(key)
			sets0[hs.h0].xormask ^= hs.h
			sets0[hs.h0].count++
			sets1[hs.h1].xormask ^= hs.h
			sets1[hs.h1].count++
			sets2[hs.h2].xormask ^= hs.h
			sets2[hs.h2].count++
		}
		// scan for values with a count of one
		Q0size := 0
		Q1size := 0
		Q2size := 0
		for i := uint32(0); i < filter.blockLength; i++ {
			if sets0[i].count == 1 {
				Q0[Q0size].index = i
				Q0[Q0size].hash = sets0[i].xormask
				Q0size++
			}
		}

		for i := uint32(0); i < filter.blockLength; i++ {
			if sets1[i].count == 1 {
				Q1[Q1size].index = i
				Q1[Q1size].hash = sets1[i].xormask
				Q1size++
			}
		}
		for i := uint32(0); i < filter.blockLength; i++ {
			if sets2[i].count == 1 {
				Q2[Q2size].index = i
				Q2[Q2size].hash = sets2[i].xormask
				Q2size++
			}
		}
		stacksize := 0
		for Q0size+Q1size+Q2size > 0 {
			for Q0size > 0 {
				Q0size--
				keyindexvar := Q0[Q0size]
				index := keyindexvar.index
				if sets0[index].count == 0 {
					continue // not actually possible after the initial scan.
				}
				hash := keyindexvar.hash
				h1 := filter.geth1(hash)
				h2 := filter.geth2(hash)
				stack[stacksize] = keyindexvar
				stacksize++
				sets1[h1].xormask ^= hash

				sets1[h1].count--
				if sets1[h1].count == 1 {
					Q1[Q1size].index = h1
					Q1[Q1size].hash = sets1[h1].xormask
					Q1size++
				}
				sets2[h2].xormask ^= hash
				sets2[h2].count--
				if sets2[h2].count == 1 {
					Q2[Q2size].index = h2
					Q2[Q2size].hash = sets2[h2].xormask
					Q2size++
				}
			}
			for Q1size > 0 {
				Q1size--
				keyindexvar := Q1[Q1size]
				index := keyindexvar.index
				if sets1[index].count == 0 {
					continue
				}
				hash := keyindexvar.hash
				h0 := filter.geth0(hash)
				h2 := filter.geth2(hash)
				keyindexvar.index += filter.blockLength
				stack[stacksize] = keyindexvar
				stacksize++
				sets0[h0].xormask ^= hash
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}
				sets2[h2].xormask ^= hash
				sets2[h2].count--
				if sets2[h2].count == 1 {
					Q2[Q2size].index = h2
					Q2[Q2size].hash = sets2[h2].xormask
					Q2size++
				}
			}
			for Q2size > 0 {
				Q2size--
				keyindexvar := Q2[Q2size]
				index := keyindexvar.index
				if sets2[index].count == 0 {
					continue
				}
				hash := keyindexvar.hash
				h0 := filter.geth0(hash)
				h1 := filter.geth1(hash)
				keyindexvar.index += 2 * filter.blockLength

				stack[stacksize] = keyindexvar
				stacksize++
				sets0[h0].xormask ^= hash
				sets0[h0].count--
				if sets0[h0].count == 1 {
					Q0[Q0size].index = h0
					Q0[Q0size].hash = sets0[h0].xormask
					Q0size++
				}
				sets1[h1].xormask ^= hash
				sets1[h1].count--
				if sets1[h1].count == 1 {
					Q1[Q1size].index = h1
					Q1[Q1size].hash = sets1[h1].xormask
					Q1size++
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
		for i := range sets2 {
			sets2[i] = xorset{0, 0}
		}
		filter.seed = splitmix64(&rngcounter)
	}

	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		val := uint8(fingerprint(ki.hash))
		if ki.index < filter.blockLength {
			val ^= filter.fingerprints[filter.geth1(ki.hash)+filter.blockLength] ^ filter.fingerprints[filter.geth2(ki.hash)+2*filter.blockLength]
		} else if ki.index < 2*filter.blockLength {
			val ^= filter.fingerprints[filter.geth0(ki.hash)] ^ filter.fingerprints[filter.geth2(ki.hash)+2*filter.blockLength]
		} else {
			val ^= filter.fingerprints[filter.geth0(ki.hash)] ^ filter.fingerprints[filter.geth1(ki.hash)+filter.blockLength]
		}
		filter.fingerprints[ki.index] = val
	}
	return filter
}
