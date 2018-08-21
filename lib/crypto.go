package lib

import (
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber"
)

func CreateDecryptionTable(limit int64, pubKey kyber.Point, secKey kyber.Scalar) {
	dummy := libunlynx.EncryptInt(pubKey, int64(limit))
	libunlynx.DecryptIntWithNeg(secKey, *dummy)
}
