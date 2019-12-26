package xorfilter

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBasic(t *testing.T) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter := Populate(keys)
	for _, v := range keys {
		assert.Equal(t, true, filter.Contains(v))
	}
	falsesize := 1000000
	matches := 0
	stat := filter.Stat()
	fmt.Println("% of empty elements in last segment", stat.LastSegmentFree)
	fmt.Println("bits per entry ", stat.BitsPerValue)
	fmt.Println("bits per entry plus", stat.BitsPerValuePlus)
	assert.Equal(t, true, stat.BitsPerValuePlus < 9.5)
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

func BenchmarkPopulate100000(b *testing.B) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)
	for i := range keys {
		keys[i] = rand.Uint64()
	}

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		Populate(keys)
	}
}

func BenchmarkContains100000(b *testing.B) {
	testsize := 10000
	keys := make([]uint64, testsize, testsize)
	for i := range keys {
		keys[i] = rand.Uint64()
	}
	filter := Populate(keys)

	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Contains(keys[n%len(keys)])
	}
}
