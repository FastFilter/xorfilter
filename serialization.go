//go:build (!amd64 && !386 && !arm && !arm64 && !ppc64le && !mipsle && !mips64le && !mips64p32le && !wasm) || appengine
// +build !amd64,!386,!arm,!arm64,!ppc64le,!mipsle,!mips64le,!mips64p32le,!wasm appengine

package xorfilter

import (
	"encoding/binary"
	"io"
)

// Save writes the filter to the writer in little endian format.
func (f *BinaryFuse[T]) Save(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, f.Seed); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentLength); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentLengthMask); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentCount); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentCountLength); err != nil {
		return err
	}
	// Write the length of Fingerprints
	fpLen := uint32(len(f.Fingerprints))
	if err := binary.Write(w, binary.LittleEndian, fpLen); err != nil {
		return err
	}
	// Write the Fingerprints
	for _, fp := range f.Fingerprints {
		if err := binary.Write(w, binary.LittleEndian, fp); err != nil {
			return err
		}
	}
	return nil
}

// LoadBinaryFuse reads the filter from the reader in little endian format.
func LoadBinaryFuse[T Unsigned](r io.Reader) (*BinaryFuse[T], error) {
	var f BinaryFuse[T]
	if err := binary.Read(r, binary.LittleEndian, &f.Seed); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentLength); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentLengthMask); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentCount); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentCountLength); err != nil {
		return nil, err
	}
	// Read the length of Fingerprints
	var fpLen uint32
	if err := binary.Read(r, binary.LittleEndian, &fpLen); err != nil {
		return nil, err
	}
	f.Fingerprints = make([]T, fpLen)
	for i := range f.Fingerprints {
		if err := binary.Read(r, binary.LittleEndian, &f.Fingerprints[i]); err != nil {
			return nil, err
		}
	}
	return &f, nil
}
