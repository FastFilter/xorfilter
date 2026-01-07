package xorfilter

// Xor8 offers a 0.3% false-positive probability
type Xor8 struct {
	Seed         uint64
	BlockLength  uint32
	Fingerprints []uint8

	// Portable, when true, ensures that multi-byte fields (Seed, BlockLength)
	// are interpreted in little-endian byte order for cross-platform compatibility.
	// For Xor8, Fingerprints are uint8 so they are unaffected by endianness.
	Portable bool
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
