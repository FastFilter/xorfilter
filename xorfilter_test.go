package xorfilter

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var rng = uint64(time.Now().UnixNano())

func TestBasic(t *testing.T) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)
	for i := range keys {
		keys[i] = splitmix64(&rng)
	}
	filter,_ := Populate(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 1000000
	matches := 0
	bpv := float64(len(filter.Fingerprints)) * 8.0 / float64(testsize)
	fmt.Println("Xor8 filter:")
	fmt.Println("bits per entry ", bpv)
	assert.Equal(t, true, bpv < 10.)
	for i := 0; i < falsesize; i++ {
		v := splitmix64(&rng)
		if filter.Contains(v) {
			matches++
		}
	}
	fpp := float64(matches) * 100.0 / float64(falsesize)
	fmt.Println("false positive rate ", fpp)
	assert.Equal(t, true, fpp < 0.40)
}

func BenchmarkPopulate100000(b *testing.B) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		b.StopTimer()
		for i := range keys {
			keys[i] = splitmix64(&rng)
		}
		b.StartTimer()
		Populate(keys)
	}
}

func BenchmarkContains100000(b *testing.B) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)
	for i := range keys {
		keys[i] = splitmix64(&rng)
	}
	filter,_ := Populate(keys)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}
