package encoding

import (
	"math"

	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib"
)

// EncodeCosim computes the elements needed to compute cosine similarity
func EncodeCosim(rijs, riks []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeCosimWithProofs(rijs, riks, pubKey, nil, []*[]int64{})
	return resultEnc, resultClear
}

// EncodeCosimWithProofs computes the elements needed to compute cosine similarity with the proof of range
func EncodeCosimWithProofs(rijs, riks []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//sum the rijs
	rijs_sum := int64(0)
	riks_sum := int64(0)
	rijs_2_sum := int64(0)
	riks_2_sum := int64(0)
	rijs_x_rijks_sum := int64(0)

	for i, el := range rijs {
		el2 := riks[i]
		rijs_sum = rijs_sum + el
		riks_sum = riks_sum + el2
		rijs_2_sum = rijs_2_sum + el*el
		riks_2_sum = riks_2_sum + el2*el2
		rijs_x_rijks_sum = rijs_x_rijks_sum + el*el2

	}
	resultClear := []int64{rijs_sum, riks_sum, rijs_2_sum, riks_2_sum, rijs_x_rijks_sum}

	result_encrypted := make([]libunlynx.CipherText, len(resultClear))
	result_randomR := make([]kyber.Scalar, len(resultClear))
	wg := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		go func(i int, v int64) {
			defer wg.Done()
			tmp, r := libdrynx.EncryptIntGetR(pubKey, v)
			result_encrypted[i] = *tmp
			result_randomR[i] = r
		}(i, v)

	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return result_encrypted, resultClear, nil
	}

	createProofs := make([]libdrynx.CreateProof, len(resultClear))
	wg = libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg.Done()
				//input range validation proof
				createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
		}

	}
	libunlynx.EndParallelize(wg)

	return result_encrypted, resultClear, createProofs
}

// DecodeCosim decodes (decrypts and computes) the cosine similarity result
func DecodeCosim(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	results_clear := make([]int64, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i, j := range result {
		go func(i int, j libunlynx.CipherText) {
			defer wg.Done()
			results_clear[i] = libunlynx.DecryptIntWithNeg(secKey, j)
		}(i, j)

	}
	libunlynx.EndParallelize(wg)

	cosim := float64(results_clear[4]) / (math.Sqrt(float64(results_clear[2])) * math.Sqrt(float64(results_clear[3])))

	return cosim

}
