package encoding_test

import (
	"go.dedis.ch/kyber/v3"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestEncodeDecodeMean tests EncodeMean and DecodeMean
func TestEncodeDecodeMean(t *testing.T) {
	//data
	inputValues := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -120}
	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	sum := int64(0)
	for _, el := range inputValues {
		sum += el
	}
	expect := float64(sum) / float64(len(inputValues))

	//function call
	resultEncrypted, _ := encoding.EncodeMean(inputValues, pubKey)
	result := encoding.DecodeMean(resultEncrypted, secKey)
	assert.Equal(t, expect, result)
}

// TestEncodeDecodeMeanWithProofs tests EncodeMean and DecodeMean with input range validation
func TestEncodeDecodeMeanWithProofs(t *testing.T) {
	//data
	inputValues := []int64{0, 10, 9, 1, 11}
	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	sum := int64(0)
	for _, el := range inputValues {
		sum += el
	}
	expect := float64(sum) / float64(len(inputValues))

	//signatures needed to check the proof
	u := []int64{2, 2}
	l := []int64{5, 3}

	ps := make([][]libdrynx.PublishSignature, 2)

	ranges := make([]*[]int64, 2)
	ps[0] = make([]libdrynx.PublishSignature, 2)
	ps[1] = make([]libdrynx.PublishSignature, 2)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 2)
	ys[1] = make([]kyber.Point, 2)
	for i := range ps[0] {
		ps[0][i] = libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u[i]))
		ps[1][i] = libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u[i]))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u[i], l[i]}
	}

	yss := make([][]kyber.Point, 2)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncrypted, _, prf := encoding.EncodeMeanWithProofs(inputValues, pubKey, ps, ranges)
	result := encoding.DecodeMean(resultEncrypted, secKey)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prf[0]), u[0], l[0], yss[0], pubKey))
	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prf[1]), u[1], l[1], yss[1], pubKey))
	assert.Equal(t, expect, result)
}
