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
	if arity == 3 {
		return uint32(2) << int(math.Round(0.831*math.Log(float64(size))+0.75+0.5))
	} else if arity == 4 {
		return uint32(1) << int(math.Round(0.936*math.Log(float64(size))-1+0.5))
	} else {
		return 65536
	}
}

func calculateSizeFactor(arity uint32, size uint32) float64 {
	if arity == 3 {
		return math.Max(1.125, 0.4+9.3/math.Log(float64(size)))
	} else if arity == 4 {
		return math.Max(1.075, 0.77+4.06/math.Log(float64(size)))
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
	capacity := uint32(math.Round(float64(size) * sizeFactor))
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
	hh := hash
	h1 ^= uint32(hh>>18) & filter.SegmentLengthMask
	h2 ^= uint32(hh) & filter.SegmentLengthMask
	return h0, h1, h2
}

// NaivePopulateBinaryFuse8 fills a BinaryFuse8 filter with provided keys.
// The caller is responsible for ensuring there are no duplicate keys provided.
// The function may return an error after too many iterations: it is almost
// surely an indication that you have duplicate keys.
// 
// You should prefer PopulateBinaryFuse8
//
func NaivePopulateBinaryFuse8(keys []uint64) (*BinaryFuse8, error) {
	size := uint32(len(keys))
	filter := &BinaryFuse8{}
	filter.initializeParameters(size)
	rngcounter := uint64(1)
	filter.Seed = splitmix64(&rngcounter)

	capacity := uint32(len(filter.Fingerprints))

	H := make([]xorset, capacity)
	alone := make([]uint32, capacity)
	reverseOrder := make([]uint64, size)
	reverseH := make([]uint8, size)

	iterations := 0
	for true {
		iterations += 1
		if iterations > MaxIterations {
			return nil, errors.New("too many iterations, you probably have duplicate keys")
		}

		// Add all keys to the construction array.
		for _, key := range keys {
			hash := mixsplit(key, filter.Seed)
			index1, index2, index3 := filter.getHashFromHash(hash)
			H[index1].count++
			H[index1].xormask ^= hash
			H[index2].count++
			H[index2].xormask ^= hash
			H[index3].count++
			H[index3].xormask ^= hash
		}
		Qsize := 0
		// Add sets with one key to the queue.
		for i := uint32(0); i < capacity; i++ {
			if H[i].count == 1 {
				alone[Qsize] = i
				Qsize++
			}
		}

		stacksize := uint32(0)
		for Qsize > 0 {
			Qsize--
			index := alone[Qsize]
			if H[index].count == 1 {
				hash := H[index].xormask
				reverseOrder[stacksize] = hash
				index1, index2, index3 := filter.getHashFromHash(hash)

				if index == index1 {
					reverseH[stacksize] = uint8(0)
				}
				if index == index2 {
					reverseH[stacksize] = uint8(1)
				}
				if index == index3 {
					reverseH[stacksize] = uint8(2)
				}
				stacksize++

				H[index1].count -= 1
				if H[index1].count == 1 {
					alone[Qsize] = index1
					Qsize++
				}
				H[index1].xormask ^= hash

				H[index2].count -= 1
				if H[index2].count == 1 {
					alone[Qsize] = index2
					Qsize++
				}
				H[index2].xormask ^= hash

				H[index3].count -= 1
				if H[index3].count == 1 {
					alone[Qsize] = index3
					Qsize++
				}
				H[index3].xormask ^= hash

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

	for i := int(size - 1); i >= 0; i-- {
		// the hash of the key we insert next
		hash := reverseOrder[i]
		// we set table[change] to the fingerprint of the key,
		// unless the other two entries are already occupied
		xor2 := uint8(fingerprint(hash))
		index1, index2, index3 := filter.getHashFromHash(hash)
		switch reverseH[i] {
		case 0:
			filter.Fingerprints[index1] = xor2 ^ filter.Fingerprints[index2] ^ filter.Fingerprints[index3]
		case 1:
			filter.Fingerprints[index2] = xor2 ^ filter.Fingerprints[index1] ^ filter.Fingerprints[index3]
		default:
			filter.Fingerprints[index3] = xor2 ^ filter.Fingerprints[index1] ^ filter.Fingerprints[index2]
		}
	}

	return filter, nil
}


// PopulateBinaryFuse8 fills a BinaryFuse8 filter with provided keys.
// The caller is responsible for ensuring there are no duplicate keys provided.
// The function may return an error after too many iterations: it is almost
// surely an indication that you have duplicate keys.
func PopulateBinaryFuse8(keys []uint64) (*BinaryFuse8, error) {
	size := uint32(len(keys))
	filter := &BinaryFuse8{}
	filter.initializeParameters(size)
	rngcounter := uint64(1)
	filter.Seed = splitmix64(&rngcounter)

	capacity := uint32(len(filter.Fingerprints))

	H := make([]xorset, capacity)
	alone := make([]uint32, capacity)
	hashes := make([]uint64, size)
	reverseOrder := make([]uint64, size)
	reverseH := make([]uint8, size)

	iterations := 0
	for true {
		iterations += 1
		if iterations > MaxIterations {
			return nil, errors.New("too many iterations, you probably have duplicate keys")
		}

		// Add all keys to the construction array.
		/*
		// We could do it as follows but it would be slower.
		for _, key := range keys {
			hash := mixsplit(key, filter.Seed)
			index1, index2, index3 := filter.getHashFromHash(hash)
			H[index1].count++
			H[index1].xormask ^= hash
			H[index2].count++
			H[index2].xormask ^= hash
			H[index3].count++
			H[index3].xormask ^= hash
		}
		// End of key addition.
		*/
		blockBits := 1
		for (1<<blockBits) < filter.SegmentCount {
			blockBits += 1
		}
		startPos := make([]int, 1 << blockBits)
		for i, key := range keys {
			hash := mixsplit(key, filter.Seed)
			hashes[i] = hash
			startPos[hash >> (64 - blockBits)] += 1
		}
		for i:= 1; i < len(startPos); i++ {
			startPos[i] += startPos[i - 1]
		}
		for _, hash := range hashes {
			idx := hash >> (64 - blockBits)
			startPos[idx] -= 1
			reverseOrder[startPos[idx]] = hash
		}
		for i := uint32(0); i < size; i++ {
			hash := reverseOrder[i]
			index1, index2, index3 := filter.getHashFromHash(hash)
			H[index1].count++
			H[index1].xormask ^= hash
			H[index2].count++
			H[index2].xormask ^= hash
			H[index3].count++
			H[index3].xormask ^= hash
		}
		// End of key addition

		Qsize := 0
		// Add sets with one key to the queue.
		for i := uint32(0); i < capacity; i++ {
			if H[i].count == 1 {
				alone[Qsize] = i
				Qsize++
			}
		}

		stacksize := uint32(0)
		for Qsize > 0 {
			Qsize--
			index := alone[Qsize]
			if H[index].count == 1 {
				hash := H[index].xormask
				reverseOrder[stacksize] = hash
				index1, index2, index3 := filter.getHashFromHash(hash)

				if index == index1 {
					reverseH[stacksize] = uint8(0)
				}
				if index == index2 {
					reverseH[stacksize] = uint8(1)
				}
				if index == index3 {
					reverseH[stacksize] = uint8(2)
				}
				stacksize++

				H[index1].count -= 1
				if H[index1].count == 1 {
					alone[Qsize] = index1
					Qsize++
				}
				H[index1].xormask ^= hash

				H[index2].count -= 1
				if H[index2].count == 1 {
					alone[Qsize] = index2
					Qsize++
				}
				H[index2].xormask ^= hash

				H[index3].count -= 1
				if H[index3].count == 1 {
					alone[Qsize] = index3
					Qsize++
				}
				H[index3].xormask ^= hash

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

	for i := int(size - 1); i >= 0; i-- {
		// the hash of the key we insert next
		hash := reverseOrder[i]
		// we set table[change] to the fingerprint of the key,
		// unless the other two entries are already occupied
		xor2 := uint8(fingerprint(hash))
		index1, index2, index3 := filter.getHashFromHash(hash)
		switch reverseH[i] {
		case 0:
			filter.Fingerprints[index1] = xor2 ^ filter.Fingerprints[index2] ^ filter.Fingerprints[index3]
		case 1:
			filter.Fingerprints[index2] = xor2 ^ filter.Fingerprints[index1] ^ filter.Fingerprints[index3]
		default:
			filter.Fingerprints[index3] = xor2 ^ filter.Fingerprints[index1] ^ filter.Fingerprints[index2]
		}
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
