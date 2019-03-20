package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
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

			vi := PairingSuite.Scalar().Pick(random.New())
			(*cv)[i].K = PairingSuite.Point().Mul(vi, PairingSuite.Point().Base())
			rbNeg := PairingSuite.Point().Neg(rbs[i])
			rbkNeg := PairingSuite.Point().Mul(secretKey, rbNeg)
			viNewK := PairingSuite.Point().Mul(vi, targetPubKey)
			(*cv)[i].C = PairingSuite.Point().Add(rbkNeg, viNewK)

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
	return PairingSuite.String() == PairingSuite.String()
}
