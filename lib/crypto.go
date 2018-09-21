package libdrynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
)

// CreateDecryptionTable generated the lookup table for decryption of all the integers in [-limit, limit]
func CreateDecryptionTable(limit int64, pubKey kyber.Point, secKey kyber.Scalar) {
	dummy := libunlynx.EncryptInt(pubKey, int64(limit))
	libunlynx.DecryptIntWithNeg(secKey, *dummy)
}

// NewKeySwitching implements the key switching operation on a ciphertext.
func NewKeySwitching(targetPubKey kyber.Point, rbs []kyber.Point, secretKey kyber.Scalar) (libunlynx.CipherVector, []kyber.Point, []kyber.Point, []kyber.Scalar) {
	length := len(rbs)

	ks2s := make([]kyber.Point, length)
	rBNegs := make([]kyber.Point, length)
	vis := make([]kyber.Scalar, length)

	wg := libunlynx.StartParallelize(length)
	cv := libunlynx.NewCipherVector(len(rbs))
	for i, v := range rbs {
		go func(i int, v kyber.Point) {
			defer wg.Done()

			vi := libunlynx.SuiTe.Scalar().Pick(random.New())
			(*cv)[i].K = libunlynx.SuiTe.Point().Mul(vi, libunlynx.SuiTe.Point().Base())
			rbNeg := libunlynx.SuiTe.Point().Neg(rbs[i])
			log.LLvl1(secretKey.String())
			rbkNeg := libunlynx.SuiTe.Point().Mul(secretKey, rbNeg)
			viNewK := libunlynx.SuiTe.Point().Mul(vi, targetPubKey)
			(*cv)[i].C = libunlynx.SuiTe.Point().Add(rbkNeg, viNewK)

			//proof
			ks2s[i] = (*cv)[i].C
			rBNegs[i] = rbNeg
			vis[i] = vi
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	return *cv, ks2s, rBNegs, vis
}

// CurvePairingTest test the type of the curve.
func CurvePairingTest() bool {
	return libunlynx.SuiTe.String() == "combined:bn256.G1"
}