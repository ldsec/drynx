package libdrynxencoding_test

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/key"
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
	uniqueValues := libdrynxencoding.Unique(inputValues)
	for i := int64(0); i < int64(len(expectedUnions)); i++ {
		expectedUnions[i] = 0
	}
	for _, entry := range uniqueValues {
		expectedUnions[entry-min] = 1
	}
	var expectedInters = expectedUnions

	//function call Union
	unionCipher, _ := libdrynxencoding.EncodeUnion(inputValues, min, max, pubKey)
	resultUnions := libdrynxencoding.DecodeUnion(unionCipher, secKey)
	//function call Intersection
	interCipher, _ := libdrynxencoding.EncodeInter(inputValues, min, max, pubKey)
	resultInters := libdrynxencoding.DecodeInter(interCipher, secKey)

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
	uniqueValues := libdrynxencoding.Unique(inputValues)
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
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
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
	resultEncryptedUnion, _, prfMin := libdrynxencoding.EncodeUnionWithProofs(inputValues, min, max, pubKey, ps, ranges)
	resultMin := libdrynxencoding.DecodeUnion(resultEncryptedUnion, secKey)
	assert.Equal(t, expectedUnions, resultMin)
	resultEncryptedInter, _, prfMax := libdrynxencoding.EncodeInterWithProofs(inputValues, min, max, pubKey, ps, ranges)
	resultInter := libdrynxencoding.DecodeInter(resultEncryptedInter, secKey)
	assert.Equal(t, expectedInters, resultInter)

	for i, v := range prfMin {
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(v), u, l, yss[i], pubKey))
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prfMax[i]), u, l, yss[i], pubKey))
	}

}
