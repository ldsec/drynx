package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib"
)

// EncodeMean computes the mean of query results
func EncodeMean(input []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeMeanWithProofs(input, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeMeanWithProofs computes the mean of query results with the proof of range
func EncodeMeanWithProofs(input []int64, pubKey kyber.Point, sigs [][]lib.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []lib.CreateProof) {
	//sum the local DP's query results
	sum := int64(0)
	for _, el := range input {
		sum += el
	}
	N := int64(len(input))
	resultClear := []int64{sum, N}

	result_encrypted := make([]libunlynx.CipherText, len(resultClear))
	result_randomR := make([]kyber.Scalar, len(resultClear))

	wg := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		go func(i int, v int64) {
			defer wg.Done()
			tmp, r := lib.EncryptIntGetR(pubKey, v)
			result_encrypted[i] = *tmp
			result_randomR[i] = r
		}(i,v)

	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return result_encrypted, resultClear, nil
	}

	createProofs := make([]lib.CreateProof, len(resultClear))
	wg1 := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createProofs[i] = lib.CreateProof{Sigs: lib.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = lib.CreateProof{Sigs: lib.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
		}

	}
	libunlynx.EndParallelize(wg1)
	return result_encrypted, resultClear, createProofs
}

// DecodeMean computes the mean of local DP's query results
func DecodeMean(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//decrypt the query results
	results_clear := make([]int64, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i, j := range result {
		go func(i int, j libunlynx.CipherText) {
			defer wg.Done()
			results_clear[i] = libunlynx.DecryptIntWithNeg(secKey, j)
		}(i,j)

	}
	libunlynx.EndParallelize(wg)
	return float64(results_clear[0]) / float64(results_clear[1])
}
