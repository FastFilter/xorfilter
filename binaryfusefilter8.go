package xorfilter

import "io"

type BinaryFuse8 BinaryFuse[uint8]

// PopulateBinaryFuse8 fills the filter with provided keys. For best results,
// the caller should avoid having too many duplicated keys.
// The function may return an error if the set is empty.
func PopulateBinaryFuse8(keys []uint64) (*BinaryFuse8, error) {
	filter, err := NewBinaryFuse[uint8](keys)
	if err != nil {
		return nil, err
	}

	return (*BinaryFuse8)(filter), nil
}

// Contains returns `true` if key is part of the set with a false positive probability of <0.4%.
func (filter *BinaryFuse8) Contains(key uint64) bool {
	return (*BinaryFuse[uint8])(filter).Contains(key)
}

// Save writes the filter to the writer in little endian format.
func (f *BinaryFuse8) Save(w io.Writer) error {
	return (*BinaryFuse[uint8])(f).Save(w)
}

// LoadBinaryFuse8 reads the filter from the reader in little endian format.
func LoadBinaryFuse8(r io.Reader) (*BinaryFuse8, error) {
	filter, err := LoadBinaryFuse[uint8](r)
	if err != nil {
		return nil, err
	}
	return (*BinaryFuse8)(filter), nil
}
