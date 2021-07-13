package crypto

import (
	c_hash "github.com/lifei/crypto/hash"
)

func Sha256(bytes []byte) []byte {
	hasher := c_hash.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}
