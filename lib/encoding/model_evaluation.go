package libdrynxencoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
)

// EncodeModelEvaluation encodes the R-score statistic at data providers
func EncodeModelEvaluation(inputY []int64, inputPreds []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeModelEvaluationWithProofs(inputY, inputPreds, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeModelEvaluationWithProofs encodes the R-score statistic at data providers with range proofs
func EncodeModelEvaluationWithProofs(inputY []int64, inputPreds []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, ranges []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynxrange.CreateProof) {
	//inputY is the list of true y values
	//inputPreds is the list of predictions

	//sum the Ys and their squares, and the square of the differences between true and predicted Ys
	sumY := int64(0)
	sumYSquare := int64(0)
	sumDiffSquare := int64(0)

	plaintextValues := make([]int64, 4)
	r := make([]kyber.Scalar, 4)

	//Encrypt the number of data samples considered
	nEncrypted, r0 := libunlynx.EncryptIntGetR(pubKey, int64(len(inputY)))
	r[0] = r0

	for i, el := range inputY {
		sumY += el
		sumYSquare += el * el
		sumDiffSquare += (inputPreds[i] - el) * (inputPreds[i] - el)
	}

	plaintextValues[0] = int64(len(inputY))
	plaintextValues[1] = sumY
	plaintextValues[2] = sumYSquare
	plaintextValues[3] = sumDiffSquare

	//Encrypt the sum of Ys
	sumYEncrypted, r1 := libunlynx.EncryptIntGetR(pubKey, sumY)
	r[1] = r1

	//Encrypt the sum of squares of Ys
	sumYSquareEncrypted, r2 := libunlynx.EncryptIntGetR(pubKey, sumYSquare)
	r[2] = r2

	//Encrypt the sum of squares of the differences between true and predicted Ys
	sumDiffSquareEncrypted, r3 := libunlynx.EncryptIntGetR(pubKey, sumDiffSquare)
	r[3] = r3

	ciphertextTuples := make([]libunlynx.CipherText, len(plaintextValues))
	ciphertextTuples[0] = *nEncrypted
	ciphertextTuples[1] = *sumYEncrypted
	ciphertextTuples[2] = *sumYSquareEncrypted
	ciphertextTuples[3] = *sumDiffSquareEncrypted

	if sigs == nil {
		return ciphertextTuples, []int64{0}, nil
	}

	//input range validation proof
	createRangeProof := make([]libdrynxrange.CreateProof, len(plaintextValues))
	wg := libunlynx.StartParallelize(len(createRangeProof))
	for i, v := range plaintextValues {
		go func(i int, v int64) {
			defer wg.Done()
			//input range validation proof
			createRangeProof[i] = libdrynxrange.CreateProof{Sigs: libdrynxrange.ReadColumn(sigs, int(i)), U: (*ranges[i])[0], L: (*ranges[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: ciphertextTuples[i]}
		}(i, v)
	}
	libunlynx.EndParallelize(wg)
	return ciphertextTuples, []int64{0}, createRangeProof
}

// DecodeModelEvaluation decrypts and computes the R-score statistic
func DecodeModelEvaluation(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//get the number of data samples
	N := libunlynx.DecryptIntWithNeg(secKey, result[0])

	//get the sum of Ys
	sumY := libunlynx.DecryptIntWithNeg(secKey, result[1])

	//get the sum of squares of Xs
	sumYSquare := libunlynx.DecryptIntWithNeg(secKey, result[2])

	//get the sum of Ys
	sumDiffSquare := libunlynx.DecryptIntWithNeg(secKey, result[3])

	B := float64(sumYSquare) - float64(sumY*sumY/N)
	return float64(1) - float64(sumDiffSquare)/B
}
