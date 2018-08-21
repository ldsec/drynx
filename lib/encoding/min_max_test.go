package encoding_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/dedis/kyber"
)

//TestEncodeDecodeMinMax tests EncodeMin and DecodeMin
func TestEncodeDecodeMinMax(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 3, 2, 15, 6, 17, 2, -5, 72, -20, 100, -190, 200}
	// key
	secKey, pubKey := libunlynx.GenKey()

	//maximum possible value taken by the attribute in question
	global_max := int64(200)
	//minimum possible value taken by the attribute in question
	global_min := int64(-200)

	//expected min
	expected_min := inputValues[0]
	//expected max
	expected_max := inputValues[0]
	for _, v := range inputValues {
		if v < expected_min {
			expected_min = v
		} else if v > expected_max {
			expected_max = v
		}
	}

	//function call min
	minCipher,_ := encoding.EncodeMin(inputValues, global_max, global_min, pubKey)
	result_min := encoding.DecodeMin(minCipher, global_min, secKey)
	//function call max
	maxCipher, _ := encoding.EncodeMax(inputValues, global_max, global_min, pubKey)
	result_max := encoding.DecodeMax(maxCipher, global_min, secKey)

	assert.Equal(t, expected_min, result_min)
	assert.Equal(t, expected_max, result_max)
}

func TestEncodeDecodeMinMaxWithProofs(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 10}
	// key
	secKey, pubKey := libunlynx.GenKey()

	//maximum possible value taken by the attribute in question
	global_max := int64(10)
	//minimum possible value taken by the attribute in question
	global_min := int64(0)

	//expected min
	expected_min := inputValues[0]
	//expected max
	expected_max := inputValues[0]
	for _, v := range inputValues {
		if v < expected_min {
			expected_min = v
		} else if v > expected_max {
			expected_max = v
		}
	}

	//signatures needed to check the proof
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)

	ps := make([][]libunlynx.PublishSignature, 2)

	ranges := make([]*[]int64, global_max-global_min+1)
	ps[0] = make([]libunlynx.PublishSignature, global_max-global_min+1)
	ps[1] = make([]libunlynx.PublishSignature, global_max-global_min+1)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, global_max-global_min+1)
	ys[1] = make([]kyber.Point, global_max-global_min+1)
	for i := range ps[0] {
		ps[0][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u))
		ps[1][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, global_max-global_min+1)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncryptedMin, _, prfMin := encoding.EncodeMinWithProofs(inputValues, global_max, global_min, pubKey, ps, ranges)
	resultMin := encoding.DecodeMin(resultEncryptedMin, global_min, secKey)
	assert.Equal(t, expected_min, resultMin)
	resultEncryptedMax, _, prfMax := encoding.EncodeMaxWithProofs(inputValues, global_max, global_min, pubKey, ps, ranges)
	resultMax := encoding.DecodeMax(resultEncryptedMax, global_min, secKey)
	assert.Equal(t, expected_max, resultMax)

	for i,v := range prfMin{
		assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(v), u, l, yss[i], pubKey))
		assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prfMax[i]), u, l, yss[i], pubKey))
	}

}