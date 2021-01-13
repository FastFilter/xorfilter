package xorfilter

import (
	"errors"
)

// The Fuse8 xor filter uses 8-bit fingerprints. It offers the same <0.4% false-positive probability
// as the xor filter, but uses less space (~9.1 bits/entry vs ~9.9 bits/entry).
//
// The Fuse8 xor filter uses the fuse data structure, which requires a large number of keys to be
// operational. Experimentally, this number is somewhere >1e5. For smaller key sets, prefer thhe
// Xor8 filter.
//
// For more information on the fuse graph data structure, see https://arxiv.org/abs/1907.04749.
// This implementation is referenced from the C implementation at https://github.com/FastFilter/xor_singleheader/pull/11.
type Fuse8 struct {
	Seed          uint64
	SegmentLength uint32
	Fingerprints  []uint8
}

type h012 struct {
	h0 uint32
	h1 uint32
	h2 uint32
}

const ARITY = 3
const SEGMENT_COUNT = 100
const SLOTS = SEGMENT_COUNT + ARITY - 1

// Contains returns `true` if key is part of the set with a false positive probability of <0.4%.
func (filter *Fuse8) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := uint8(fingerprint(hash))
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	r3 := uint32((0xBF58476D1CE4E5B9 * hash) >> 32)
	seg := reduce(r0, SEGMENT_COUNT)
	h0 := seg*filter.SegmentLength + reduce(r1, filter.SegmentLength)
	h1 := (seg+1)*filter.SegmentLength + reduce(r2, filter.SegmentLength)
	h2 := (seg+2)*filter.SegmentLength + reduce(r3, filter.SegmentLength)
	return f == (filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^
		filter.Fingerprints[h2])
}

func (filter *Fuse8) makeKeyHashes(k uint64) hashes {
	hash := mixsplit(k, filter.Seed)
	answer := hashes{}
	answer.h = hash
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	r3 := uint32((0xBF58476D1CE4E5B9 * hash) >> 32)
	seg := reduce(r0, SEGMENT_COUNT)
	answer.h0 = (seg+0)*filter.SegmentLength + reduce(r1, filter.SegmentLength)
	answer.h1 = (seg+1)*filter.SegmentLength + reduce(r2, filter.SegmentLength)
	answer.h2 = (seg+2)*filter.SegmentLength + reduce(r3, filter.SegmentLength)
	return answer
}

func (filter *Fuse8) geth012(hash uint64) h012 {
	answer := h012{}
	r0 := uint32(hash)
	r1 := uint32(rotl64(hash, 21))
	r2 := uint32(rotl64(hash, 42))
	r3 := uint32((0xBF58476D1CE4E5B9 * hash) >> 32)
	seg := reduce(r0, SEGMENT_COUNT)
	answer.h0 = (seg+0)*filter.SegmentLength + reduce(r1, filter.SegmentLength)
	answer.h1 = (seg+1)*filter.SegmentLength + reduce(r2, filter.SegmentLength)
	answer.h2 = (seg+2)*filter.SegmentLength + reduce(r3, filter.SegmentLength)
	return answer
}

// Populate fills a Fuse8 filter with provided keys.
// The caller is responsible for ensuring there are no duplicate keys provided.
// The function may return an error after too many iterations: it is almost
// surely an indication that you have duplicate keys.
func PopulateFuse8(keys []uint64) (*Fuse8, error) {
	const FUSE_OVERHEAD = 1.0 / 0.879
	const FUSE_CONSTANT = 1024 // todo: determine value
	// ref: Algorithm 3
	size := len(keys)
	capacity := uint32(FUSE_OVERHEAD*float64(size) + FUSE_CONSTANT)
	capacity = capacity / SLOTS * SLOTS
	rngcounter := uint64(1)

	filter := &Fuse8{}
	filter.SegmentLength = capacity / SLOTS
	filter.Fingerprints = make([]uint8, capacity, capacity)
	filter.Seed = splitmix64(&rngcounter)

	H := make([]xorset, capacity, capacity)
	Q := make([]keyindex, capacity, capacity)
	stack := make([]keyindex, size, size)
	iterations := 0
	for true {
		iterations += 1
		if iterations > MaxIterations {
			return nil, errors.New("too many iterations, you probably have duplicate keys")
		}

		// Add all keys to the construction array.
		for _, key := range keys {
			hs := filter.makeKeyHashes(key)

			H[hs.h0].xormask ^= hs.h
			H[hs.h0].count++
			H[hs.h1].xormask ^= hs.h
			H[hs.h1].count++
			H[hs.h2].xormask ^= hs.h
			H[hs.h2].count++
		}

		Qsize := 0
		// Add sets with one key to the queue.
		for i := uint32(0); i < capacity; i++ {
			if H[i].count == 1 {
				Q[Qsize].index = i
				Q[Qsize].hash = H[i].xormask
				Qsize++
			}
		}

		stacksize := 0
		for Qsize > 0 {
			Qsize--
			ki := Q[Qsize]
			index := ki.index
			if H[index].count == 0 {
				continue // not actually possible after the initial scan
			}

			hash := ki.hash
			hs := filter.geth012(hash)

			stack[stacksize] = ki
			stacksize++

			// Remove key added to stack from all sets in the construction array and
			// enqueue sets that now have one key.
			H[hs.h0].xormask ^= hash
			H[hs.h0].count--
			if H[hs.h0].count == 1 {
				Q[Qsize].index = hs.h0
				Q[Qsize].hash = H[hs.h0].xormask
				Qsize++
			}
			H[hs.h1].xormask ^= hash
			H[hs.h1].count--
			if H[hs.h1].count == 1 {
				Q[Qsize].index = hs.h1
				Q[Qsize].hash = H[hs.h1].xormask
				Qsize++
			}
			H[hs.h2].xormask ^= hash
			H[hs.h2].count--
			if H[hs.h2].count == 1 {
				Q[Qsize].index = hs.h2
				Q[Qsize].hash = H[hs.h2].xormask
				Qsize++
			}
		}

		if stacksize == size {
			// Success
			break
		}
		for i := range H {
			H[i] = xorset{0, 0}
		}
		filter.Seed = splitmix64(&rngcounter)
	}

	// ref: Algorithm 4
	stacksize := size
	for stacksize > 0 {
		stacksize--
		ki := stack[stacksize]
		hs := filter.geth012(ki.hash)
		fp := uint8(fingerprint(ki.hash))
		switch ki.index {
		case hs.h0:
			fp ^= filter.Fingerprints[hs.h1] ^ filter.Fingerprints[hs.h2]
		case hs.h1:
			fp ^= filter.Fingerprints[hs.h0] ^ filter.Fingerprints[hs.h2]
		default:
			fp ^= filter.Fingerprints[hs.h0] ^ filter.Fingerprints[hs.h1]
		}
		filter.Fingerprints[ki.index] = fp
	}

	return filter, nil
}
