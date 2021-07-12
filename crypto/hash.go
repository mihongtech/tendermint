package crypto

import (
	"github.com/tjfoc/gmsm/sm3"
)

func Sha256(bytes []byte) []byte {
	hasher := sm3.New()
	hasher.Write(bytes)
	return hasher.Sum(nil)
}
