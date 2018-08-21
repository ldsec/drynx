package encoding_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/dedis/kyber"
)

//TestEncodeDecodeModelEvaluation tests EncodeModelEvaluation and DecodeModelEvaluation
func TestEncodeDecodeModelEvaluation(t *testing.T) {
	//data
	inputValues_y := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67, -72}
	inputValues_y_pred := []int64{32, 12, 23, 4, 13, -72, 12, 8, 23, 67, 2}

	//These sets of values should yield an R^2 coefficient of 1
	/*inputValues_y := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}
	inputValues_y_pred := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}

	//These sets of values should yield an R^2 coefficient of -Inf
	inputValues_y := []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	inputValues_y_pred := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}*/

	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	N := int64(len(inputValues_y))
	sum_y := int64(0)
	sum_y_square := int64(0)
	sum_diff_square := int64(0)
	for i, el := range inputValues_y {
		sum_y += el
		sum_y_square += el * el
		sum_diff_square += (inputValues_y_pred[i] - el) * (inputValues_y_pred[i] - el)
	}
	B := float64(sum_y_square) - float64(sum_y*sum_y/N)
	R_expect := float64(1) - float64(sum_diff_square)/B

	//function call
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _ = encoding.EncodeModelEvaluation(inputValues_y, inputValues_y_pred, pubKey)
	result := encoding.DecodeModelEvaluation(resultEncrypted, secKey)

	assert.Equal(t, R_expect, result)
}

//TestEncodeDecodeModelEvaluationWithProofs tests EncodeModelEvaluationWithProofs and DecodeModelEvaluationWithProofs
func TestEncodeDecodeModelEvaluationWithProofs(t *testing.T) {
	//data
	inputValues_y := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 6, -7}
	inputValues_y_pred := []int64{32, 12, 23, 4, 13, -7, 12, 8, 2, 6, 2}

	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	N := int64(len(inputValues_y))
	sum_y := int64(0)
	sum_y_square := int64(0)
	sum_diff_square := int64(0)
	for i, el := range inputValues_y {
		sum_y += el
		sum_y_square += el * el
		sum_diff_square += (inputValues_y_pred[i] - el) * (inputValues_y_pred[i] - el)
	}
	B := float64(sum_y_square) - float64(sum_y*sum_y/N)
	R_expect := float64(1) - float64(sum_diff_square)/B

	//signatures needed to check the proof
	u := []int64{2, 2, 2, 2}
	l := []int64{8, 12, 12, 12}

	ps := make([][]libunlynx.PublishSignature, 2)
	ranges := make([]*[]int64, 4)
	ps[0] = make([]libunlynx.PublishSignature, 4)
	ps[1] = make([]libunlynx.PublishSignature, 4)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 4)
	ys[1] = make([]kyber.Point, 4)
	for i := range ps[0] {
		ps[0][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u[i]))
		ps[1][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u[i]))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u[i], l[i]}
	}

	yss := make([][]kyber.Point, 4)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncrypted, _, prf := encoding.EncodeModelEvaluationWithProofs(inputValues_y, inputValues_y_pred, pubKey, ps, ranges)
	result := encoding.DecodeModelEvaluation(resultEncrypted, secKey)

	assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prf[0]), u[0], l[0], yss[0], pubKey))
	assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prf[1]), u[1], l[1], yss[1], pubKey))
	assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prf[2]), u[2], l[2], yss[2], pubKey))
	assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prf[3]), u[3], l[3], yss[3], pubKey))
	assert.Equal(t, R_expect, result)
}
