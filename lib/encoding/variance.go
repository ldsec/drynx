package encoding

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
)

// EncodeVariance computes the variance of query results
func EncodeVariance(input []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeVarianceWithProofs(input, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeVarianceWithProofs computes the variance of query results with the proof of range
func EncodeVarianceWithProofs(input []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//sum the local DP's query results, and their squares as well
	sum := int64(0)
	sumSquares := int64(0)
	for _, el := range input {
		sum += el
		sumSquares += el * el
	}
	N := int64(len(input))
	resultClear := []int64{sum, N, sumSquares}

	resultEncrypteds := make([]libunlynx.CipherText, len(resultClear))
	resultRandomRS := make([]kyber.Scalar, len(resultClear))

	//encrypt the local DP's query result
	wg := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		go func(i int, v int64) {
			defer wg.Done()
			tmp, r := libunlynx.EncryptIntGetR(pubKey, v)
			resultEncrypteds[i] = *tmp
			resultRandomRS[i] = r
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return resultEncrypteds, resultClear, nil
	}

	createProofs := make([]libdrynx.CreateProof, len(resultClear))
	wg1 := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: resultRandomRS[i], CaPub: pubKey, Cipher: resultEncrypteds[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: resultRandomRS[i], CaPub: pubKey, Cipher: resultEncrypteds[i]}
		}

	}
	libunlynx.EndParallelize(wg1)
	return resultEncrypteds, resultClear, createProofs
}

//DecodeVariance computes the variance of local DP's query results
func DecodeVariance(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//decrypt the query results
	resultsClears := make([]int64, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i, j := range result {
		go func(i int, j libunlynx.CipherText) {
			defer wg.Done()
			resultsClears[i] = libunlynx.DecryptIntWithNeg(secKey, j)
		}(i, j)

	}
	libunlynx.EndParallelize(wg)
	//compute and return the variance
	mean := float64(resultsClears[0]) / float64(resultsClears[1])
	return float64(resultsClears[2])/float64(resultsClears[1]) - mean*mean
}
