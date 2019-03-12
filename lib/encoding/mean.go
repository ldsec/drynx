package encoding

import (
	"go.dedis.ch/kyber/v3"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
)

// EncodeMean computes the mean of query results
func EncodeMean(input []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeMeanWithProofs(input, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeMeanWithProofs computes the mean of query results with the proof of range
func EncodeMeanWithProofs(input []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//sum the local DP's query results
	sum := int64(0)
	for _, el := range input {
		sum += el
	}
	N := int64(len(input))
	resultClear := []int64{sum, N}

	resultEncrypted := make([]libunlynx.CipherText, len(resultClear))
	resultRandomR := make([]kyber.Scalar, len(resultClear))

	wg := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		go func(i int, v int64) {
			defer wg.Done()
			tmp, r := libunlynx.EncryptIntGetR(pubKey, v)
			resultEncrypted[i] = *tmp
			resultRandomR[i] = r
		}(i, v)

	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return resultEncrypted, resultClear, nil
	}

	createProofs := make([]libdrynx.CreateProof, len(resultClear))
	wg1 := libunlynx.StartParallelize(len(resultClear))
	for i, v := range resultClear {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: resultRandomR[i], CaPub: pubKey, Cipher: resultEncrypted[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: resultRandomR[i], CaPub: pubKey, Cipher: resultEncrypted[i]}
		}

	}
	libunlynx.EndParallelize(wg1)
	return resultEncrypted, resultClear, createProofs
}

// DecodeMean computes the mean of local DP's query results
func DecodeMean(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//decrypt the query results
	resultsClear := make([]int64, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i, j := range result {
		go func(i int, j libunlynx.CipherText) {
			defer wg.Done()
			resultsClear[i] = libunlynx.DecryptIntWithNeg(secKey, j)
		}(i, j)

	}
	libunlynx.EndParallelize(wg)
	return float64(resultsClear[0]) / float64(resultsClear[1])
}
