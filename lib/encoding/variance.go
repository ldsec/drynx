package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)

// EncodeVariance computes the variance of query results
func EncodeVariance(input []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeVarianceWithProofs(input, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeVarianceWithProofs computes the variance of query results with the proof of range
func EncodeVarianceWithProofs(input []int64, pubKey kyber.Point, sigs [][]libunlynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libunlynx.CreateProof) {
	//sum the local DP's query results, and their squares as well
	sum := int64(0)
	sum_squares := int64(0)
	for _, el := range input {
		sum += el
		sum_squares += el * el
	}
	N := int64(len(input))
	resultClear := []int64{sum, N, sum_squares}

	result_encrypted := make([]libunlynx.CipherText, len(resultClear))
	result_randomR := make([]kyber.Scalar, len(resultClear))

	//encrypt the local DP's query result
	wg := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		go func(i int, v int64) {
			defer wg.Done()
			tmp, r := libunlynx.EncryptIntGetR(pubKey, v)
			result_encrypted[i] = *tmp
			result_randomR[i] = r
		}(i,v)
	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return result_encrypted, resultClear, nil
	}

	createProofs := make([]libunlynx.CreateProof, len(resultClear))
	wg1 := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createProofs[i] = libunlynx.CreateProof{Sigs: libunlynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = libunlynx.CreateProof{Sigs: libunlynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: result_randomR[i], CaPub: pubKey, Cipher: result_encrypted[i]}
		}

	}
	libunlynx.EndParallelize(wg1)
	return result_encrypted, resultClear, createProofs
}

//DecodeVariance computes the variance of local DP's query results
func DecodeVariance(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//decrypt the query results
	results_clear := make([]int64, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i, j := range result {
		go func(i int, j libunlynx.CipherText) {
			defer wg.Done()
			results_clear[i] = libunlynx.DecryptIntWithNeg(secKey, j)
		}(i , j)

	}
	libunlynx.EndParallelize(wg)
	//compute and return the variance
	mean := float64(results_clear[0]) / float64(results_clear[1])
	return float64(results_clear[2])/float64(results_clear[1]) - mean*mean
}
