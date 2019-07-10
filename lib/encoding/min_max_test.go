package libdrynxencoding_test

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"testing"
)

//TestEncodeDecodeMinMax tests EncodeMin and DecodeMin
func TestEncodeDecodeMinMax(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 3, 2, 15, 6, 17, 2, -5, 72, -20, 100, -190, 200}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	//maximum possible value taken by the attribute in question
	globalMax := int64(200)
	//minimum possible value taken by the attribute in question
	globalMin := int64(-200)

	//expected min
	expectedMin := inputValues[0]
	//expected max
	expectedMax := inputValues[0]
	for _, v := range inputValues {
		if v < expectedMin {
			expectedMin = v
		} else if v > expectedMax {
			expectedMax = v
		}
	}

	//function call min
	minCipher, _ := libdrynxencoding.EncodeMin(inputValues, globalMax, globalMin, pubKey)
	resultMin := libdrynxencoding.DecodeMin(minCipher, globalMin, secKey)
	//function call max
	maxCipher, _ := libdrynxencoding.EncodeMax(inputValues, globalMax, globalMin, pubKey)
	resultMax := libdrynxencoding.DecodeMax(maxCipher, globalMin, secKey)

	assert.Equal(t, expectedMin, resultMin)
	assert.Equal(t, expectedMax, resultMax)
}

func TestEncodeDecodeMinMaxWithProofs(t *testing.T) {
	//data
	inputValues := []int64{1, 2, 10}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	//maximum possible value taken by the attribute in question
	globalMax := int64(10)
	//minimum possible value taken by the attribute in question
	globalMin := int64(0)

	//expected min
	expectedMin := inputValues[0]
	//expected max
	expectedMax := inputValues[0]
	for _, v := range inputValues {
		if v < expectedMin {
			expectedMin = v
		} else if v > expectedMax {
			expectedMax = v
		}
	}

	//signatures needed to check the proof
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)

	ps := make([][]libdrynx.PublishSignature, 2)

	ranges := make([]*[]int64, globalMax-globalMin+1)
	ps[0] = make([]libdrynx.PublishSignature, globalMax-globalMin+1)
	ps[1] = make([]libdrynx.PublishSignature, globalMax-globalMin+1)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, globalMax-globalMin+1)
	ys[1] = make([]kyber.Point, globalMax-globalMin+1)
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, globalMax-globalMin+1)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncryptedMin, _, prfMin := libdrynxencoding.EncodeMinWithProofs(inputValues, globalMax, globalMin, pubKey, ps, ranges)
	resultMin := libdrynxencoding.DecodeMin(resultEncryptedMin, globalMin, secKey)
	assert.Equal(t, expectedMin, resultMin)
	resultEncryptedMax, _, prfMax := libdrynxencoding.EncodeMaxWithProofs(inputValues, globalMax, globalMin, pubKey, ps, ranges)
	resultMax := libdrynxencoding.DecodeMax(resultEncryptedMax, globalMin, secKey)
	assert.Equal(t, expectedMax, resultMax)

	for i, v := range prfMin {
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(v), u, l, yss[i], pubKey))
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prfMax[i]), u, l, yss[i], pubKey))
	}

}
