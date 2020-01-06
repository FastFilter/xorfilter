package xorfilter

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

const NUM_KEYS = 1e6

func TestFuse8Basic(t *testing.T) {
	testsize := 1000000
	keys := make([]uint64, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter, _ := PopulateFuse8(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 1000000
	matches := 0
	bpv := float64(len(filter.Fingerprints)) * 8.0 / float64(testsize)
	fmt.Println("Fuse8 filter:")
	fmt.Println("bits per entry ", bpv)
	assert.Equal(t, true, bpv < 9.101)
	for i := 0; i < falsesize; i++ {
		v := rand.Uint64()
		if filter.Contains(v) {
			matches++
		}
	}
	fpp := float64(matches) * 100.0 / float64(falsesize)
	fmt.Println("false positive rate ", fpp)
	assert.Equal(t, true, fpp < 0.40)
}

func BenchmarkFuse8Populate1000000(b *testing.B) {
	keys := make([]uint64, NUM_KEYS, NUM_KEYS)
	for i := range keys {
		keys[i] = rand.Uint64()
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		PopulateFuse8(keys)
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
