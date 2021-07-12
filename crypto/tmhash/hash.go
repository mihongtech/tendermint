package tmhash

import (
	"github.com/tjfoc/gmsm/sm3"
	"hash"
)

const (
	Size      = 32
	BlockSize = 64
)

// New returns a new hash.Hash.
func New() hash.Hash {
	return sm3.New()
}

// Sum returns the SHA256 of the bz.
func Sum(bz []byte) []byte {
	h := sm3.Sm3Sum(bz)
	return h[:]
}

//-------------------------------------------------------------

const (
	TruncatedSize = 20
)

type sha256trunc struct {
	sha256 hash.Hash
}

func (h sha256trunc) Write(p []byte) (n int, err error) {
	return h.sha256.Write(p)
}
func (h sha256trunc) Sum(b []byte) []byte {
	shasum := h.sha256.Sum(b)
	return shasum[:TruncatedSize]
}

func (h sha256trunc) Reset() {
	h.sha256.Reset()
}

func (h sha256trunc) Size() int {
	return TruncatedSize
}

func (h sha256trunc) BlockSize() int {
	return h.sha256.BlockSize()
}

// NewTruncated returns a new hash.Hash.
func NewTruncated() hash.Hash {
	return sha256trunc{
		sha256: sm3.New(),
	}
}

// SumTruncated returns the first 20 bytes of SHA256 of the bz.
func SumTruncated(bz []byte) []byte {
	hash := sm3.Sm3Sum(bz)
	return hash[:TruncatedSize]
}
