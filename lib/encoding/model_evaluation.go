package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib"
)

// EncodeModelEvaluation encodes the R-score statistic at data providers
func EncodeModelEvaluation(input_y []int64, input_pred []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeModelEvaluationWithProofs(input_y, input_pred, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeModelEvaluationWithProofs encodes the R-score statistic at data providers with range proofs
func EncodeModelEvaluationWithProofs(input_y []int64, input_pred []int64, pubKey kyber.Point, sigs [][]lib.PublishSignature, ranges []*[]int64) ([]libunlynx.CipherText, []int64, []lib.CreateProof) {
	//input_y is the list of true y values
	//input_pred is the list of predictions

	//sum the Ys and their squares, and the square of the differences between true and predicted Ys
	sum_y := int64(0)
	sum_y_square := int64(0)
	sum_diff_square := int64(0)

	plaintext_values := make([]int64, 4)
	r := make([]kyber.Scalar, 4)

	//Encrypt the number of data samples considered
	N_Encrypted, r0 := lib.EncryptIntGetR(pubKey, int64(len(input_y)))
	r[0] = r0

	for i, el := range input_y {
		sum_y += el
		sum_y_square += el * el
		sum_diff_square += (input_pred[i] - el) * (input_pred[i] - el)
	}

	plaintext_values[0] = int64(len(input_y))
	plaintext_values[1] = sum_y
	plaintext_values[2] = sum_y_square
	plaintext_values[3] = sum_diff_square

	//Encrypt the sum of Ys
	sum_y_Encrypted, r1 := lib.EncryptIntGetR(pubKey, sum_y)
	r[1] = r1

	//Encrypt the sum of squares of Ys
	sum_y_square_Encrypted, r2 := lib.EncryptIntGetR(pubKey, sum_y_square)
	r[2] = r2

	//Encrypt the sum of squares of the differences between true and predicted Ys
	sum_diff_square_Encrypted, r3 := lib.EncryptIntGetR(pubKey, sum_diff_square)
	r[3] = r3

	Ciphertext_Tuple := make([]libunlynx.CipherText, len(plaintext_values))
	Ciphertext_Tuple[0] = *N_Encrypted
	Ciphertext_Tuple[1] = *sum_y_Encrypted
	Ciphertext_Tuple[2] = *sum_y_square_Encrypted
	Ciphertext_Tuple[3] = *sum_diff_square_Encrypted

	if sigs == nil {return Ciphertext_Tuple, []int64{0}, nil}

	//input range validation proof
	createRangeProof := make([]lib.CreateProof, len(plaintext_values))
	wg := libunlynx.StartParallelize(len(createRangeProof))
	for i, v := range plaintext_values {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg.Done()
				//input range validation proof
				createRangeProof[i] = lib.CreateProof{Sigs: lib.ReadColumn(sigs, int(i)), U: (*ranges[i])[0], L: (*ranges[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
				}(i, v)
		} else {
			//input range validation proof
			createRangeProof[i] = lib.CreateProof{Sigs: lib.ReadColumn(sigs, int(i)), U: (*ranges[i])[0], L: (*ranges[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
		}
	}
	libunlynx.EndParallelize(wg)
	return Ciphertext_Tuple, []int64{0}, createRangeProof
}

// DecodeModelEvaluation decrypts and computes the R-score statistic
func DecodeModelEvaluation(result []libunlynx.CipherText, secKey kyber.Scalar) float64 {
	//get the number of data samples
	N := libunlynx.DecryptIntWithNeg(secKey, result[0])

	//get the sum of Ys
	sum_y := libunlynx.DecryptIntWithNeg(secKey, result[1])

	//get the sum of squares of Xs
	sum_y_square := libunlynx.DecryptIntWithNeg(secKey, result[2])

	//get the sum of Ys
	sum_diff_square := libunlynx.DecryptIntWithNeg(secKey, result[3])

	B := float64(sum_y_square) - float64(sum_y*sum_y/N)
	return float64(1) - float64(sum_diff_square)/B
}
