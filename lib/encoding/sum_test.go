package encoding_test

import (
	"github.com/dedis/kyber"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestEncodeDecodeSum tests EncodeSum and DecodeSum
func TestEncodeDecodeSum(t *testing.T) {
	//data
	inputValues := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -12000}
	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	expect := int64(0)
	for _, el := range inputValues {
		expect += el
	}
	//function call
	resultEncrypted, _ := encoding.EncodeSum(inputValues, pubKey)
	result := encoding.DecodeSum(*resultEncrypted, secKey)

	assert.Equal(t, expect, result)
}

// TestEncodeDecodeSumWithProofs tests EncodeSum and DecodeSum with input range validation
func TestEncodeDecodeSumWithProofs(t *testing.T) {
	//data
	inputValues := []int64{0, 10, 9}
	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	expect := int64(0)
	for _, el := range inputValues {
		expect += el
	}

	//signatures needed to check the proof
	u := int64(2)
	l := int64(6)
	ps := []libdrynx.PublishSignature{libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u))}

	//function call
	resultEncrypted, _, prf := encoding.EncodeSumWithProofs(inputValues, pubKey, ps, l, u)
	result := encoding.DecodeSum(*resultEncrypted, secKey)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prf[0]), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expect, result)
}
