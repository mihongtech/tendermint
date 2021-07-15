package types

import (
	"github.com/mihongtech/crypto/signature"

	cryptoenc "github.com/mihongtech/crypto/encoding"
)

//func Ed25519ValidatorUpdate(pk []byte, power int64) ValidatorUpdate {
//	pke := ed25519.PubKey(pk)
//
//	pkp, err := cryptoenc.PubKeyToProto(pke)
//	if err != nil {
//		panic(err)
//	}
//
//	return ValidatorUpdate{
//		// Address:
//		PubKey: pkp,
//		Power:  power,
//	}
//}

func UpdateValidator(pk []byte, power int64, keyType string) ValidatorUpdate {
	pke := signature.BytesToPublicKey(pk, keyType)
	pkp, err := cryptoenc.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		// Address:
		PubKey: pkp,
		Power:  power,
	}
}
