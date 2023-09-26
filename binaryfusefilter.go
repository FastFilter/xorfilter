package xorfilter

import (
	"errors"
	"math"
	"math/bits"
)

type BinaryFuse8 struct {
	Seed               uint64
	SegmentLength      uint32
	SegmentLengthMask  uint32
	SegmentCount       uint32
	SegmentCountLength uint32

	Fingerprints []uint8
}

func calculateSegmentLength(arity uint32, size uint32) uint32 {
	// These parameters are very sensitive. Replacing 'floor' by 'round' can
	// substantially affect the construction time.
	if size == 0 {
		return 4
	}
	if arity == 3 {
		return uint32(1) << int(math.Floor(math.Log(float64(size))/math.Log(3.33)+2.25))
	} else if arity == 4 {
		return uint32(1) << int(math.Floor(math.Log(float64(size))/math.Log(2.91)-0.5))
	} else {
		return 65536
	}
}

func calculateSizeFactor(arity uint32, size uint32) float64 {
	if arity == 3 {
		return math.Max(1.125, 0.875+0.25*math.Log(1000000)/math.Log(float64(size)))
	} else if arity == 4 {
		return math.Max(1.075, 0.77+0.305*math.Log(600000)/math.Log(float64(size)))
	} else {
		return 2.0
	}
}

func (filter *BinaryFuse8) initializeParameters(size uint32) {
	arity := uint32(3)
	filter.SegmentLength = calculateSegmentLength(arity, size)
	if filter.SegmentLength > 262144 {
		filter.SegmentLength = 262144
	}
	filter.SegmentLengthMask = filter.SegmentLength - 1
	sizeFactor := calculateSizeFactor(arity, size)
	capacity := uint32(0)
	if size > 1 {
		capacity = uint32(math.Round(float64(size) * sizeFactor))
	}
	initSegmentCount := (capacity+filter.SegmentLength-1)/filter.SegmentLength - (arity - 1)
	arrayLength := (initSegmentCount + arity - 1) * filter.SegmentLength
	filter.SegmentCount = (arrayLength + filter.SegmentLength - 1) / filter.SegmentLength
	if filter.SegmentCount <= arity-1 {
		filter.SegmentCount = 1
	} else {
		filter.SegmentCount = filter.SegmentCount - (arity - 1)
	}
	arrayLength = (filter.SegmentCount + arity - 1) * filter.SegmentLength
	filter.SegmentCountLength = filter.SegmentCount * filter.SegmentLength
	filter.Fingerprints = make([]uint8, arrayLength)
}

func (filter *BinaryFuse8) getHashFromHash(hash uint64) (uint32, uint32, uint32) {
	hi, _ := bits.Mul64(hash, uint64(filter.SegmentCountLength))
	h0 := uint32(hi)
	h1 := h0 + filter.SegmentLength
	h2 := h1 + filter.SegmentLength
	h1 ^= uint32(hash>>18) & filter.SegmentLengthMask
	h2 ^= uint32(hash) & filter.SegmentLengthMask
	return h0, h1, h2
}

func mod3(x uint8) uint8 {
	if x > 2 {
		x -= 3
	}
	return x
}

// PopulateBinaryFuse8 fills the filter with provided keys. For best results,
// the caller should avoid having too many duplicated keys.
// The function may return an error if the set is empty.
func PopulateBinaryFuse8(keys []uint64) (*BinaryFuse8, error) {
	size := uint32(len(keys))
	filter := &BinaryFuse8{}
	filter.initializeParameters(size)
	rngcounter := uint64(1)
	filter.Seed = splitmix64(&rngcounter)
	capacity := uint32(len(filter.Fingerprints))

	alone := make([]uint32, capacity)
	// the lowest 2 bits are the h index (0, 1, or 2)
	// so we only have 6 bits for counting;
	// but that's sufficient
	t2count := make([]uint8, capacity)
	reverseH := make([]uint8, size)

	t2hash := make([]uint64, capacity)
	reverseOrder := make([]uint64, size+1)
	reverseOrder[size] = 1

	// the array h0, h1, h2, h0, h1, h2
	var h012 [6]uint32
	// this could be used to compute the mod3
	// tabmod3 := [5]uint8{0,1,2,0,1}
	iterations := 0
	for true {
		iterations += 1
		if iterations > MaxIterations {
			// The probability of this happening is lower than the
			// the cosmic-ray probability (i.e., a cosmic ray corrupts your system).
			return nil, errors.New("too many iterations")
		}

		blockBits := 1
		for (1 << blockBits) < filter.SegmentCount {
			blockBits += 1
		}
		startPos := make([]uint, 1<<blockBits)
		for i, _ := range startPos {
			// important: we do not want i * size to overflow!!!
			startPos[i] = uint((uint64(i) * uint64(size)) >> blockBits)
		}
		for _, key := range keys {
			hash := mixsplit(key, filter.Seed)
			segment_index := hash >> (64 - blockBits)
			for reverseOrder[startPos[segment_index]] != 0 {
				segment_index++
				segment_index &= (1 << blockBits) - 1
			}
			reverseOrder[startPos[segment_index]] = hash
			startPos[segment_index] += 1
		}
		error := 0
		duplicates := uint32(0)

		for i := uint32(0); i < size; i++ {
			hash := reverseOrder[i]
			index1, index2, index3 := filter.getHashFromHash(hash)
			t2count[index1] += 4
			// t2count[index1] ^= 0 // noop
			t2hash[index1] ^= hash
			t2count[index2] += 4
			t2count[index2] ^= 1
			t2hash[index2] ^= hash
			t2count[index3] += 4
			t2count[index3] ^= 2
			t2hash[index3] ^= hash
			// If we have duplicated hash values, then it is likely that
			// the next comparison is true
			if t2hash[index1]&t2hash[index2]&t2hash[index3] == 0 {
				// next we do the actual test
				if ((t2hash[index1] == 0) && (t2count[index1] == 8)) || ((t2hash[index2] == 0) && (t2count[index2] == 8)) || ((t2hash[index3] == 0) && (t2count[index3] == 8)) {
					duplicates += 1
					t2count[index1] -= 4
					t2hash[index1] ^= hash
					t2count[index2] -= 4
					t2count[index2] ^= 1
					t2hash[index2] ^= hash
					t2count[index3] -= 4
					t2count[index3] ^= 2
					t2hash[index3] ^= hash
				}
			}
			if t2count[index1] < 4 {
				error = 1
			}
			if t2count[index2] < 4 {
				error = 1
			}
			if t2count[index3] < 4 {
				error = 1
			}
		}
		if error == 1 {
			for i := uint32(0); i < size; i++ {
				reverseOrder[i] = 0
			}
			for i := uint32(0); i < capacity; i++ {
				t2count[i] = 0
				t2hash[i] = 0
			}
			filter.Seed = splitmix64(&rngcounter)
			continue
		}

		// End of key addition

		Qsize := 0
		// Add sets with one key to the queue.
		for i := uint32(0); i < capacity; i++ {
			alone[Qsize] = i
			if (t2count[i] >> 2) == 1 {
				Qsize++
			}
		}
		stacksize := uint32(0)
		for Qsize > 0 {
			Qsize--
			index := alone[Qsize]
			if (t2count[index] >> 2) == 1 {
				hash := t2hash[index]
				found := t2count[index] & 3
				reverseH[stacksize] = found
				reverseOrder[stacksize] = hash
				stacksize++

				index1, index2, index3 := filter.getHashFromHash(hash)

				h012[1] = index2
				h012[2] = index3
				h012[3] = index1
				h012[4] = h012[1]

				other_index1 := h012[found+1]
				alone[Qsize] = other_index1
				if (t2count[other_index1] >> 2) == 2 {
					Qsize++
				}
				t2count[other_index1] -= 4
				t2count[other_index1] ^= mod3(found + 1) // could use this instead: tabmod3[found+1]
				t2hash[other_index1] ^= hash

				other_index2 := h012[found+2]
				alone[Qsize] = other_index2
				if (t2count[other_index2] >> 2) == 2 {
					Qsize++
				}
				t2count[other_index2] -= 4
				t2count[other_index2] ^= mod3(found + 2) // could use this instead: tabmod3[found+2]
				t2hash[other_index2] ^= hash
			}
		}

		if stacksize+duplicates == size {
			// Success
			size = stacksize
			break
		} else if duplicates > 0 {
			// Duplicates were found, but we did not
			// manage to remove them all. We may simply sort the key to
			// solve the issue. This will run in time O(n log n) and it
			// mutates the input.
			keys = pruneDuplicates(keys)
		}
		for i := uint32(0); i < size; i++ {
			reverseOrder[i] = 0
		}
		for i := uint32(0); i < capacity; i++ {
			t2count[i] = 0
			t2hash[i] = 0
		}
		filter.Seed = splitmix64(&rngcounter)
	}
	if size == 0 {
		return filter, nil
	}

	for i := int(size - 1); i >= 0; i-- {
		// the hash of the key we insert next
		hash := reverseOrder[i]
		xor2 := uint8(fingerprint(hash))
		index1, index2, index3 := filter.getHashFromHash(hash)
		found := reverseH[i]
		h012[0] = index1
		h012[1] = index2
		h012[2] = index3
		h012[3] = h012[0]
		h012[4] = h012[1]
		filter.Fingerprints[h012[found]] = xor2 ^ filter.Fingerprints[h012[found+1]] ^ filter.Fingerprints[h012[found+2]]
	}

	return filter, nil
}

// Contains returns `true` if key is part of the set with a false positive probability of <0.4%.
func (filter *BinaryFuse8) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := uint8(fingerprint(hash))
	h0, h1, h2 := filter.getHashFromHash(hash)
	f ^= filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2]
	return f == 0
}
