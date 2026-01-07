package xorfilter

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
)

func TestBinaryFuse8Serialization(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300}
	filter, err := PopulateBinaryFuse8(keys)
	if err != nil {
		t.Fatal(err)
	}

	// Test generic serialization
	var buf bytes.Buffer
	err = filter.Save(&buf)
	if err != nil {
		t.Fatal(err)
	}

	loadedFilter, err := LoadBinaryFuse8(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(filter, loadedFilter) {
		t.Error("Generic serialization: Filters do not match after save/load")
	}

	for _, key := range keys {
		if !loadedFilter.Contains(key) {
			t.Errorf("Generic serialization: Key %d not found in loaded filter", key)
		}
	}
}

func TestBinaryFuseSerializationGeneric(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300}
	filter, err := NewBinaryFuse[uint16](keys)
	if err != nil {
		t.Fatal(err)
	}

	// Test generic serialization
	var buf bytes.Buffer
	err = filter.Save(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if "wVwCiewtCpEIAAAABwAAAAEAAAAIAAAAGAAAAAAAAABY7/rBAAAAAAoqAAA2kPb5AAAAAAAAAAAAAAAAuLkw2QAAAAAAAH1sAAAAAA==" != base64.StdEncoding.EncodeToString(buf.Bytes()) {
		t.Log("Base64 serialized data:", base64.StdEncoding.EncodeToString(buf.Bytes()))
		t.Error("Generic serialization: Unexpected serialized data")
	}

	loadedFilter, err := LoadBinaryFuse[uint16](&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(filter, loadedFilter) {
		t.Error("Generic serialization: Filters do not match after save/load")
	}

	for _, key := range keys {
		if !loadedFilter.Contains(key) {
			t.Errorf("Generic serialization: Key %d not found in loaded filter", key)
		}
	}
}
