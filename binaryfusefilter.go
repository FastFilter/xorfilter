package xorfilter

import (
	"errors"
	"math"
	"math/bits"
	"unsafe"
)

type Unsigned interface {
	~uint8 | ~uint16 | ~uint32
}

type BinaryFuse[T Unsigned] struct {
	Seed               uint64
	SegmentLength      uint32
	SegmentLengthMask  uint32
	SegmentCount       uint32
	SegmentCountLength uint32

	Fingerprints []T
}

// NewBinaryFuse creates a binary fuse filter with provided keys. For best
// results, the caller should avoid having too many duplicated keys.
//
// The function can mutate the given keys slice to remove duplicates.
//
// The function may return an error if the set is empty.
func NewBinaryFuse[T Unsigned](keys []uint64) (*BinaryFuse[T], error) {
	var b BinaryFuseBuilder
	filter, err := BuildBinaryFuse[T](&b, keys)
	if err != nil {
		return nil, err
	}
	return &filter, nil
}

// BinaryFuseBuilder can be used to reuse memory allocations across multiple
// BinaryFuse builds.
//
// An empty BinaryFuseBuilder can be used, and its internal memory will grow as
// needed over time. MakeBinaryFuseBuilder can also be used to pre-initialize
// for a certain size.
type BinaryFuseBuilder struct {
	alone        []uint32
	t2hash       []uint64
	reverseOrder []uint64
	t2count      []uint8
	reverseH     []uint8
	startPos     []uint32
	fingerprints []uint32
}

// MakeBinaryFuseBuilder creates a BinaryFuseBuilder with enough preallocated
// memory to allow building of binary fuse filters with fingerprint type T
// without allocations.
//
// Note that the builder can be used with a smaller fingerprint type without
// reallocations. If it is used with a larger fingerprint type, there will be
// one reallocation for the fingerprints slice.
func MakeBinaryFuseBuilder[T Unsigned](initialSize int) BinaryFuseBuilder {
	var b BinaryFuseBuilder
	var filter BinaryFuse[T]
	size := uint32(initialSize)
	filter.initializeParameters(&b, size)
	capacity := uint32(len(filter.Fingerprints))
	reuseBuffer(&b.alone, capacity)
	reuseBuffer(&b.t2count, capacity)
	reuseBuffer(&b.reverseH, size)

	reuseBuffer(&b.t2hash, capacity)
	reuseBuffer(&b.reverseOrder, size+1)
	// The startPos array needs to be large enough for smaller sizes which use a
	// smaller segment length. Also, we dynamically try a smaller segment length
	// in some cases.
	reuseBuffer(&b.startPos, 2<<bits.Len32(filter.SegmentCount+1))
	return b
}

// BuildBinaryFuse creates a binary fuse filter with provided keys, reusing
// buffers from the BinaryFuseBuilder if possible. For best results, the caller
// should avoid having too many duplicated keys.
//
// The Fingerprints slice in the resulting filter is owned by the builder; it
// is only valid until the BinaryFuseBuilder is used again.
//
// The function can mutate the given keys slice to remove duplicates.
//
// The function may return an error if the set is empty.
func BuildBinaryFuse[T Unsigned](b *BinaryFuseBuilder, keys []uint64) (BinaryFuse[T], error) {
	f, _, err := buildBinaryFuse[T](b, keys)
	return f, err
}

func buildBinaryFuse[T Unsigned](b *BinaryFuseBuilder, keys []uint64) (_ BinaryFuse[T], iterations int, _ error) {
	size := uint32(len(keys))
	var filter BinaryFuse[T]
	filter.initializeParameters(b, size)
	rngcounter := uint64(1)
	filter.Seed = splitmix64(&rngcounter)
	capacity := uint32(len(filter.Fingerprints))

	alone := reuseBuffer(&b.alone, capacity)
	// the lowest 2 bits are the h index (0, 1, or 2)
	// so we only have 6 bits for counting;
	// but that's sufficient
	t2count := reuseBuffer(&b.t2count, capacity)
	reverseH := reuseBuffer(&b.reverseH, size)

	t2hash := reuseBuffer(&b.t2hash, capacity)
	reverseOrder := reuseBuffer(&b.reverseOrder, size+1)
	reverseOrder[size] = 1

	// the array h0, h1, h2, h0, h1, h2
	var h012 [6]uint32
	// this could be used to compute the mod3
	// tabmod3 := [5]uint8{0,1,2,0,1}
	for {
		iterations += 1
		if iterations > MaxIterations {
			// The probability of this happening is lower than the cosmic-ray
			// probability (i.e., a cosmic ray corrupts your system).
			return BinaryFuse[T]{}, iterations, errors.New("too many iterations")
		}
		if size > 4 && size < 1_000_000 {
			// The segment length is calculated using an empirical formula. For some
			// sizes, the segment length is too large and leads to many iterations.
			// Once every four iterations, use the previous segment length while
			// keeping the same capacity. See TestBinaryFuseBoundarySizes.
			switch iterations % 4 {
			case 2:
				// Switch to smaller segment size.
				filter.SegmentLength /= 2
				filter.SegmentLengthMask = filter.SegmentLength - 1
				filter.SegmentCount = filter.SegmentCount*2 + 2
				filter.SegmentCountLength = filter.SegmentCount * filter.SegmentLength
			case 3:
				// Restore the calculated segment size.
				filter.SegmentLength *= 2
				filter.SegmentLengthMask = filter.SegmentLength - 1
				filter.SegmentCount = filter.SegmentCount/2 - 1
				filter.SegmentCountLength = filter.SegmentCount * filter.SegmentLength
			}
		}

		blockBits := 1
		for (1 << blockBits) < filter.SegmentCount {
			blockBits += 1
		}
		startPos := reuseBuffer(&b.startPos, 1<<blockBits)
		for i := range startPos {
			// important: we do not want i * size to overflow!!!
			startPos[i] = uint32((uint64(i) * uint64(size)) >> blockBits)
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
				t2count[other_index1] ^= filter.mod3(found + 1) // could use this instead: tabmod3[found+1]
				t2hash[other_index1] ^= hash

				other_index2 := h012[found+2]
				alone[Qsize] = other_index2
				if (t2count[other_index2] >> 2) == 2 {
					Qsize++
				}
				t2count[other_index2] -= 4
				t2count[other_index2] ^= filter.mod3(found + 2) // could use this instead: tabmod3[found+2]
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
		return filter, iterations, nil
	}

	for i := int(size - 1); i >= 0; i-- {
		// the hash of the key we insert next
		hash := reverseOrder[i]
		xor2 := T(fingerprint(hash))
		index1, index2, index3 := filter.getHashFromHash(hash)
		found := reverseH[i]
		h012[0] = index1
		h012[1] = index2
		h012[2] = index3
		h012[3] = h012[0]
		h012[4] = h012[1]
		filter.Fingerprints[h012[found]] = xor2 ^ filter.Fingerprints[h012[found+1]] ^ filter.Fingerprints[h012[found+2]]
	}

	return filter, iterations, nil
}

func (filter *BinaryFuse[T]) initializeParameters(b *BinaryFuseBuilder, size uint32) {
	arity := uint32(3)
	filter.SegmentLength = calculateSegmentLength(arity, size)
	if filter.SegmentLength > 262144 {
		filter.SegmentLength = 262144
	}
	filter.SegmentLengthMask = filter.SegmentLength - 1
	capacity := uint32(0)
	if size > 1 {
		sizeFactor := calculateSizeFactor(arity, size)
		capacity = uint32(math.Round(float64(size) * sizeFactor))
	}
	totalSegmentCount := (capacity + filter.SegmentLength - 1) / filter.SegmentLength
	if totalSegmentCount < arity {
		totalSegmentCount = arity
	}
	filter.SegmentCount = totalSegmentCount - (arity - 1)
	filter.SegmentCountLength = filter.SegmentCount * filter.SegmentLength

	// Allocate fingerprints slice.
	numFingerprints := totalSegmentCount * filter.SegmentLength
	// Our backing buffer is a []uint32. Figure out how many uint32s we need
	// to back a []T of the requested size.
	bufSize := (numFingerprints*uint32(unsafe.Sizeof(T(0))) + 3) / 4
	buf := reuseBuffer(&b.fingerprints, bufSize)
	filter.Fingerprints = unsafe.Slice((*T)(unsafe.Pointer(unsafe.SliceData(buf))), numFingerprints)
}

func (filter *BinaryFuse[T]) mod3(x uint8) uint8 {
	if x > 2 {
		x -= 3
	}

	return x
}

func (filter *BinaryFuse[T]) getHashFromHash(hash uint64) (uint32, uint32, uint32) {
	hi, _ := bits.Mul64(hash, uint64(filter.SegmentCountLength))
	h0 := uint32(hi)
	h1 := h0 + filter.SegmentLength
	h2 := h1 + filter.SegmentLength
	h1 ^= uint32(hash>>18) & filter.SegmentLengthMask
	h2 ^= uint32(hash) & filter.SegmentLengthMask
	return h0, h1, h2
}

// Contains returns `true` if key is part of the set with a false positive probability.
func (filter *BinaryFuse[T]) Contains(key uint64) bool {
	hash := mixsplit(key, filter.Seed)
	f := T(fingerprint(hash))
	h0, h1, h2 := filter.getHashFromHash(hash)
	f ^= filter.Fingerprints[h0] ^ filter.Fingerprints[h1] ^ filter.Fingerprints[h2]
	return f == 0
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

// reuseBuffer returns a zeroed slice of the given size, reusing the previous
// one if possible.
func reuseBuffer[T uint8 | uint32 | uint64](buf *[]T, size uint32) []T {
	// The compiler recognizes this pattern and doesn't allocate a temporary
	// slice. This pattern is used in slices.Grow().
	*buf = append((*buf)[:0], make([]T, size)...)
	return *buf
}
