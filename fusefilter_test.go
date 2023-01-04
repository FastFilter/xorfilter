package xorfilter

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFuse8Basic(t *testing.T) {
	keys := make([]uint64, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateFuse8(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 10000000
	matches := 0
	bpv := float64(len(filter.Fingerprints)) * 8.0 / float64(NUM_KEYS)
	fmt.Println("Fuse8 filter:")
	fmt.Println("bits per entry ", bpv)
	for i := 0; i < falsesize; i++ {
		v := rand.Uint64()
		if filter.Contains(v) {
			matches++
		}
	}
	fpp := float64(matches) * 100.0 / float64(falsesize)
	fmt.Println("false positive rate ", fpp)
	assert.Equal(t, true, fpp < 0.40)
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
		filter, _ = PopulateFuse8(keys)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}

	}
}

func TestFuse8Small(t *testing.T) {
	keys := make([]uint64, SMALL_NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateFuse8(keys)
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
	fpp := float64(matches) * 100.0 / float64(falsesize)
	assert.Equal(t, true, fpp < 0.40)
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
		filter, _ = PopulateFuse8(keys)
		for _, v := range keys {
			assert.Equal(t, true, filter.Contains(v))
		}

	}
}

func BenchmarkConstructFuse8(b *testing.B) {
	bigrandomarrayInit()
	b.ResetTimer()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		PopulateFuse8(bigrandomarray)
	}
}

func BenchmarkFuse8Populate10000000(b *testing.B) {
	keys := make([]uint64, NUM_KEYS, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PopulateFuse8(keys)
	}
}

func Test_DuplicateKeysFuse(t *testing.T) {
	keys := []uint64{1, 77, 31, 241, 303, 303}
	_, err := PopulateFuse8(keys)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func BenchmarkFuse8Contains1000000(b *testing.B) {
	keys := make([]uint64, NUM_KEYS, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateFuse8(keys)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}

var fusedbig *Fuse8

func fusedbigInit() {
	fmt.Println("Fuse setup")
	keys := make([]uint64, 50000000, 50000000)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	fusedbig, _ = PopulateFuse8(keys)
	fmt.Println("Fuse setup ok")
}

func BenchmarkFuse8Contains50000000(b *testing.B) {
	if fusedbig == nil {
		fusedbigInit()
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		fusedbig.Contains(rand.Uint64())
	}
}
