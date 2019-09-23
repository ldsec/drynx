package libdrynxencoding_test

import (
	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/encoding"
	"github.com/ldsec/drynx/lib/range"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"testing"
)

//TestEncodeDecodeModelEvaluation tests EncodeModelEvaluation and DecodeModelEvaluation
func TestEncodeDecodeModelEvaluation(t *testing.T) {
	//data
	inputValuesY := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67, -72}
	inputValuesYPreds := []int64{32, 12, 23, 4, 13, -72, 12, 8, 23, 67, 2}

	//These sets of values should yield an R^2 coefficient of 1
	/*inputValuesY := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}
	inputValuesYPreds := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}

	//These sets of values should yield an R^2 coefficient of -Inf
	inputValuesY := []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	inputValuesYPreds := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 67}*/

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	N := int64(len(inputValuesY))
	sumY := int64(0)
	sumYSquare := int64(0)
	sumDiffSquare := int64(0)
	for i, el := range inputValuesY {
		sumY += el
		sumYSquare += el * el
		sumDiffSquare += (inputValuesYPreds[i] - el) * (inputValuesYPreds[i] - el)
	}
	B := float64(sumYSquare) - float64(sumY*sumY/N)
	rExpect := float64(1) - float64(sumDiffSquare)/B

	//function call
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _ = libdrynxencoding.EncodeModelEvaluation(inputValuesY, inputValuesYPreds, pubKey)
	result := libdrynxencoding.DecodeModelEvaluation(resultEncrypted, secKey)

	assert.Equal(t, rExpect, result)
}

//TestEncodeDecodeModelEvaluationWithProofs tests EncodeModelEvaluationWithProofs and DecodeModelEvaluationWithProofs
func TestEncodeDecodeModelEvaluationWithProofs(t *testing.T) {
	//data
	inputValuesY := []int64{1, 2, 3, 4, 5, 6, 7, 8, 1, 6, -7}
	inputValuesYPreds := []int64{32, 12, 23, 4, 13, -7, 12, 8, 2, 6, 2}

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	N := int64(len(inputValuesY))
	sumY := int64(0)
	sumYSquare := int64(0)
	sumDiffSquare := int64(0)
	for i, el := range inputValuesY {
		sumY += el
		sumYSquare += el * el
		sumDiffSquare += (inputValuesYPreds[i] - el) * (inputValuesYPreds[i] - el)
	}
	B := float64(sumYSquare) - float64(sumY*sumY/N)
	rExpect := float64(1) - float64(sumDiffSquare)/B

	//signatures needed to check the proof
	u := []int64{2, 2, 2, 2}
	l := []int64{8, 12, 12, 12}

	ps := make([][]libdrynx.PublishSignature, 2)
	ranges := make([]*[]int64, 4)
	ps[0] = make([]libdrynx.PublishSignature, 4)
	ps[1] = make([]libdrynx.PublishSignature, 4)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 4)
	ys[1] = make([]kyber.Point, 4)
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
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
	resultEncrypted, _, prf := libdrynxencoding.EncodeModelEvaluationWithProofs(inputValuesY, inputValuesYPreds, pubKey, ps, ranges)
	result := libdrynxencoding.DecodeModelEvaluation(resultEncrypted, secKey)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[0]), u[0], l[0], yss[0], pubKey))
	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[1]), u[1], l[1], yss[1], pubKey))
	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[2]), u[2], l[2], yss[2], pubKey))
	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[3]), u[3], l[3], yss[3], pubKey))
	assert.Equal(t, rExpect, result)
}
