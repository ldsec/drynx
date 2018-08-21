package encoding_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/dedis/kyber"
)

//TestEncodeDecodeUnionInter tests EncodeUnion and DecodeUnion
func TestEncodeDecodeUnionInter(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 3, 1, 5, 1, 2, 3}
	// key
	secKey, pubKey := libunlynx.GenKey()

	//maximum value taken by the attribute in question
	max := int64(10)
	//minimum value taken by the attribute in question
	min := int64(0)

	expected_union := make([]int64, max-min+1)
	unique_values := encoding.Unique(inputValues)
	for i := int64(0); i < int64(len(expected_union)); i++ {
		expected_union[i] = 0
	}
	for _, entry := range unique_values {
		expected_union[entry-min] = 1
	}
	var expected_inter = expected_union

	//function call Union
	unionCipher, _ := encoding.EncodeUnion(inputValues, min, max, pubKey)
	result_union := encoding.DecodeUnion(unionCipher, secKey)
	//function call Intersection
	interCipher, _ := encoding.EncodeInter(inputValues, min, max, pubKey)
	result_inter := encoding.DecodeInter(interCipher, secKey)

	assert.Equal(t, expected_union, result_union)
	assert.Equal(t, expected_inter, result_inter)
}

func TestEncodeDecodeUnionInterWithProofs(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 3, 1, 5, 1, 2, 3}
	// key
	secKey, pubKey := libunlynx.GenKey()

	//maximum value taken by the attribute in question
	max := int64(10)
	//minimum value taken by the attribute in question
	min := int64(0)

	expected_union := make([]int64, max-min+1)
	unique_values := encoding.Unique(inputValues)
	for i := int64(0); i < int64(len(expected_union)); i++ {
		expected_union[i] = 0
	}
	for _, entry := range unique_values {
		expected_union[entry-min] = 1
	}
	var expected_inter = expected_union

	//signatures needed to check the proof
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)

	ps := make([][]libunlynx.PublishSignature, 2)

	ranges := make([]*[]int64, max-min+1)
	ps[0] = make([]libunlynx.PublishSignature, max-min+1)
	ps[1] = make([]libunlynx.PublishSignature, max-min+1)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, max-min+1)
	ys[1] = make([]kyber.Point, max-min+1)
	for i := range ps[0] {
		ps[0][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u))
		ps[1][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, max-min+1)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncryptedUnion, _, prfMin := encoding.EncodeUnionWithProofs(inputValues, min, max, pubKey, ps, ranges)
	resultMin := encoding.DecodeUnion(resultEncryptedUnion, secKey)
	assert.Equal(t, expected_union, resultMin)
	resultEncryptedInter, _, prfMax := encoding.EncodeInterWithProofs(inputValues, min, max, pubKey, ps, ranges)
	resultInter := encoding.DecodeInter(resultEncryptedInter, secKey)
	assert.Equal(t, expected_inter, resultInter)

	for i,v := range prfMin{
		assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(v), u, l, yss[i], pubKey))
		assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prfMax[i]), u, l, yss[i], pubKey))
	}


}