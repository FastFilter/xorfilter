# xorfilter: Go library implementing xor filters


Bloom filters are used to quickly check whether an element is part of a set.
Xor filters are a faster and more concise alternative to Bloom filters.
They are also smaller than cuckoo filters.

<img src="figures/comparison.png" width="50%"/>


We are assuming that your set is made of 64-bit integers. If you have strings
or other data structures, you need to hash them first to a 64-bit integer. It
is not important to have a good hash function, but collision should be unlikely
(~1/2^64).

The current implementation has a false positive rate of about 0.3% and a memory usage
of less than 9 bits per entry for sizeable sets.

You construct the filter as follows:

```Go
filter := xorfilter.Populate(keys) // keys is of type []uint64
```
It turns an object of type `Xor8`.

You can then query it as follows:


```Go
filter.Contains(v) // v is of type uint64
```

It will *always* return true if v was part of the initial construction (`Populate`) and almost always
return false otherwise.


Though the filter itself does not use much memory, 
the construction of the filter needs about 64 bytes of memory per set entry. 

For persistence, you only need to serialize the following data structure:

```Go
type Xor8 struct {
	seed         uint64
	blockLength  uint32
	fingerprints []uint8
}
```
