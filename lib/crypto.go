package lib

import (
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"sync"
)

func CreateDecryptionTable(limit int64, pubKey kyber.Point, secKey kyber.Scalar) {
	dummy := libunlynx.EncryptInt(pubKey, int64(limit))
	libunlynx.DecryptIntWithNeg(secKey, *dummy)
}

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

// EncryptPoint creates an elliptic curve point from a non-encrypted point and encrypt it using ElGamal encryption.
func EncryptPoint(pubkey kyber.Point, M kyber.Point) (*libunlynx.CipherText, kyber.Scalar) {
	B := libunlynx.SuiTe.Point().Base()
	r := libunlynx.SuiTe.Scalar().Pick(random.New()) // ephemeral private key
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := libunlynx.SuiTe.Point().Mul(r, B)      // ephemeral DH public key
	S := libunlynx.SuiTe.Point().Mul(r, pubkey) // ephemeral DH shared secret
	C := libunlynx.SuiTe.Point().Add(S, M)      // message blinded with secret
	return &libunlynx.CipherText{K, C}, r
}

// EncryptInt encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptIntGetR(pubkey kyber.Point, integer int64) (*libunlynx.CipherText, kyber.Scalar) {
	encryption, r := EncryptPoint(pubkey, libunlynx.IntToPoint(integer))
	return encryption, r
}

// EncryptScalar encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptScalar(pubkey kyber.Point, scalar kyber.Scalar) *libunlynx.CipherText {
	encryption, _ := EncryptPoint(pubkey, libunlynx.SuiTe.Point().Mul(scalar, libunlynx.SuiTe.Point().Base()))
	return encryption
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer to it.
func EncryptIntVectorGetRs(pubkey kyber.Point, intArray []int64) (*libunlynx.CipherVector, []kyber.Scalar) {
	var wg sync.WaitGroup
	cv := make(libunlynx.CipherVector, len(intArray))
	rs := make([]kyber.Scalar, len(intArray))
	if libunlynx.PARALLELIZE {
		for i := 0; i < len(intArray); i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(intArray)); j++ {
					tmpCv, tmpR := EncryptIntGetR(pubkey, intArray[j+i])
					cv[j+i] = *tmpCv
					rs[j+i] = tmpR
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, n := range intArray {
			tmpCv, tmpR := EncryptIntGetR(pubkey, n)
			cv[i] = *tmpCv
			rs[i] = tmpR
		}
	}

	return &cv, rs
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer to it.
func EncryptScalarVector(pubkey kyber.Point, intArray []kyber.Scalar) *libunlynx.CipherVector {
	var wg sync.WaitGroup
	cv := make(libunlynx.CipherVector, len(intArray))
	if libunlynx.PARALLELIZE {
		for i := 0; i < len(intArray); i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(intArray)); j++ {
					cv[j+i] = *EncryptScalar(pubkey, intArray[j+i])
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, n := range intArray {
			cv[i] = *EncryptScalar(pubkey, n)
		}
	}

	return &cv
}

func CurvePairingTest() bool {
	return libunlynx.SuiTe.String() == "combined:bn256.G1"
}

// Equal checks equality between ciphervector.
func Equal(cv *libunlynx.CipherVector, cv2 *libunlynx.CipherVector) bool {
	if cv == nil || cv2 == nil {
		return cv == cv2
	}

	if len(*cv) != len(*cv2) {
		return false
	}

	for i := range *cv2 {
		if !EqualCipherText(&(*cv)[i], &(*cv2)[i]) {
			return false
		}
	}
	return true
}

// Equal checks equality between ciphertexts.
func EqualCipherText(c *libunlynx.CipherText, c2 *libunlynx.CipherText) bool {
	return c2.K.Equal(c.K) && c2.C.Equal(c.C)
}