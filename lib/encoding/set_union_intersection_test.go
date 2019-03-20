package encoding_test

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

//TestEncodeDecodeUnionInter tests EncodeUnion and DecodeUnion
func TestEncodeDecodeUnionInter(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	//data
	inputValues := []int64{1, 2, 3, 1, 5, 1, 2, 3}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	//maximum value taken by the attribute in question
	max := int64(10)
	//minimum value taken by the attribute in question
	min := int64(0)

	expectedUnions := make([]int64, max-min+1)
	uniqueValues := encoding.Unique(inputValues)
	for i := int64(0); i < int64(len(expectedUnions)); i++ {
		expectedUnions[i] = 0
	}
	for _, entry := range uniqueValues {
		expectedUnions[entry-min] = 1
	}
	var expectedInters = expectedUnions

	//function call Union
	unionCipher, _ := encoding.EncodeUnion(inputValues, min, max, pubKey)
	resultUnions := encoding.DecodeUnion(unionCipher, secKey)
	//function call Intersection
	interCipher, _ := encoding.EncodeInter(inputValues, min, max, pubKey)
	resultInters := encoding.DecodeInter(interCipher, secKey)

	assert.Equal(t, expectedUnions, resultUnions)
	assert.Equal(t, expectedInters, resultInters)
}

func TestEncodeDecodeUnionInterWithProofs(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 3, 1, 5, 1, 2, 3}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	//maximum value taken by the attribute in question
	max := int64(10)
	//minimum value taken by the attribute in question
	min := int64(0)

	expectedUnions := make([]int64, max-min+1)
	uniqueValues := encoding.Unique(inputValues)
	for i := int64(0); i < int64(len(expectedUnions)); i++ {
		expectedUnions[i] = 0
	}
	for _, entry := range uniqueValues {
		expectedUnions[entry-min] = 1
	}
	var expectedInters = expectedUnions

	//signatures needed to check the proof
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)

	ps := make([][]libdrynx.PublishSignature, 2)

	ranges := make([]*[]int64, max-min+1)
	ps[0] = make([]libdrynx.PublishSignature, max-min+1)
	ps[1] = make([]libdrynx.PublishSignature, max-min+1)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, max-min+1)
	ys[1] = make([]kyber.Point, max-min+1)
	for i := range ps[0] {
		ps[0][i] = libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u))
		ps[1][i] = libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u))
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
	assert.Equal(t, expectedUnions, resultMin)
	resultEncryptedInter, _, prfMax := encoding.EncodeInterWithProofs(inputValues, min, max, pubKey, ps, ranges)
	resultInter := encoding.DecodeInter(resultEncryptedInter, secKey)
	assert.Equal(t, expectedInters, resultInter)

	for i, v := range prfMin {
		assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(v), u, l, yss[i], pubKey))
		assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prfMax[i]), u, l, yss[i], pubKey))
	}

}
