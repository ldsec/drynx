package encoding_test

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/lca1/drynx/lib"
)

//TestEncodeDecodeFrequencyCount tests EncodeFreqCount and DecodeFreqCount
func TestEncodeDecodeFrequencyCount(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	//data
	max := int64(12)
	min := int64(-1)
	inputValues := []int64{-1, 0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 3, 2}
	// key
	secKey, pubKey := libunlynx.GenKey()
	lib.CreateDecryptionTable(10000, pubKey, secKey)

	//expected results
	expect := make([]int64, max-min+1)
	for i := int64(0); i <= max-min; i++ {
		expect[i] = 0
	}

	//get the frequency count for all integer values in the range {1, 2, ..., max}
	for _, el := range inputValues {
		expect[el-min] += 1
	}

	//function call
	resultEncrypted, _ := encoding.EncodeFreqCount(inputValues, min, max, pubKey)
	result := encoding.DecodeFreqCount(resultEncrypted, secKey)
	assert.Equal(t, expect, result)
}

// TestEncodeDecodeFrequencyCountWithProofs tests EncodeFreqCount and DecodeFreqCount with input range validation
func TestEncodeDecodeFrequencyCountWithProofs(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	//data
	max := int64(12)
	min := int64(-1)
	inputValues := []int64{-1, 0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 12, 3, 2}
	// key
	secKey, pubKey := libunlynx.GenKey()
	lib.CreateDecryptionTable(10000, pubKey, secKey)

	//expected results
	expect := make([]int64, max-min+1)
	for i := int64(0); i <= max-min; i++ {
		expect[i] = 0
	}

	//get the frequency count for all integer values in the range {1, 2, ..., max}
	for _, el := range inputValues {
		expect[el-min] += 1
	}

	//signatures needed to check the proof; create signatures for 2 servers and all DPs outputs
	u := int64(2)
	l := int64(10)
	ps := make([][]lib.PublishSignature, 2)

	ranges := make([]*[]int64, len(expect))
	ps[0] = make([]lib.PublishSignature, len(expect))
	ps[1] = make([]lib.PublishSignature, len(expect))
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, len(expect))
	ys[1] = make([]kyber.Point, len(expect))
	for i := range ps[0] {
		ps[0][i] = lib.PublishSignatureBytesToPublishSignatures(lib.InitRangeProofSignature(u))
		ps[1][i] = lib.PublishSignatureBytesToPublishSignatures(lib.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, len(expect))
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncrypted, _, prf := encoding.EncodeFreqCountWithProofs(inputValues, min, max, pubKey, ps, ranges)
	result := encoding.DecodeFreqCount(resultEncrypted, secKey)

	for i := 0; int64(i) <= max-min; i++ {
		assert.True(t, lib.RangeProofVerification(lib.CreatePredicateRangeProofForAllServ(prf[i]), (*ranges[i])[0], (*ranges[i])[1], yss[i], pubKey))
	}
	assert.Equal(t, expect, result)

}
