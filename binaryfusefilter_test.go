package xorfilter

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

const NUM_KEYS = 1e6
const SMALL_NUM_KEYS = 100


func TestBinaryFuse8Basic(t *testing.T) {
	keys := make([]uint64, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateBinaryFuse8(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 10000000
	matches := 0
	bpv := float64(len(filter.Fingerprints)) * 8.0 / float64(NUM_KEYS)
	fmt.Println("Binary Fuse8 filter:")
	fmt.Println("bits per entry ", bpv)
	for i := 0; i < falsesize; i++ {
		v := rand.Uint64()
		if filter.Contains(v) {
			matches++
		}
	}
	fpp := float64(matches) * 100.0 / float64(falsesize)
	fmt.Println("false positive rate ", fpp)
	cut := 1000
	if cut > NUM_KEYS {
		cut = NUM_KEYS
	}
	keys = keys[:cut]
	for trial := 0; trial < 10; trial++ {
		rand.Seed(int64(trial))
		for i := range keys {
			keys[i] = rand.Uint64()
		}
		filter, _ = PopulateBinaryFuse8(keys)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}

	}
}


func TestBinaryFuse8Small(t *testing.T) {
	keys := make([]uint64, SMALL_NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateBinaryFuse8(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 10000000
	matches := 0

	for i := 0; i < falsesize; i++ {
		v := rand.Uint64()
		if filter.Contains(v) {
			matches++
		}
	}
	cut := 1000
	if cut > SMALL_NUM_KEYS {
		cut = SMALL_NUM_KEYS
	}
	keys = keys[:cut]
	for trial := 0; trial < 10; trial++ {
		rand.Seed(int64(trial))
		for i := range keys {
			keys[i] = rand.Uint64()
		}
		filter, _ = PopulateBinaryFuse8(keys)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}

	}
}


func BenchmarkBinaryFuse8Populate1000000(b *testing.B) {
	keys := make([]uint64, NUM_KEYS, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PopulateBinaryFuse8(keys)
	}
}

func Test_ZeroSet(t *testing.T) {
	keys := []uint64{}
	_, err := PopulateBinaryFuse8(keys)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func Test_DuplicateKeysBinaryFuseDup(t *testing.T) {
	keys := []uint64{303, 1, 77, 31, 241, 303}
	_, err := PopulateBinaryFuse8(keys)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

var bogusbinary *BinaryFuse8


func BenchmarkConstructBinaryFuse8(b *testing.B) {
	bigrandomarrayInit()
	b.ResetTimer()
	b.ReportAllocs()	
	for n := 0; n < b.N; n++ {
		PopulateBinaryFuse8(bigrandomarray)
	}
}


func BenchmarkBinaryFuse8Contains1000000(b *testing.B) {
	keys := make([]uint64, NUM_KEYS, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateBinaryFuse8(keys)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}


var binaryfusedbig *BinaryFuse8

func binaryfusedbigInit() {
	fmt.Println("Binary Fuse setup")
	keys := make([]uint64, 50000000, 50000000)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	binaryfusedbig, _ = PopulateBinaryFuse8(keys)
	fmt.Println("Binary Fuse setup ok")
}

func BenchmarkBinaryFuse8Contains50000000(b *testing.B) {
	if binaryfusedbig == nil {
		binaryfusedbigInit()
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		binaryfusedbig.Contains(rand.Uint64())
	}
}
