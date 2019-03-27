package libdrynxencoding_test

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestEncodeDecodeSum tests EncodeSum and DecodeSum
func TestEncodeDecodeSum(t *testing.T) {
	//data
	inputValues := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -12000}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	expect := int64(0)
	for _, el := range inputValues {
		expect += el
	}
	//function call
	resultEncrypted, _ := libdrynxencoding.EncodeSum(inputValues, pubKey)
	result := libdrynxencoding.DecodeSum(*resultEncrypted, secKey)

	assert.Equal(t, expect, result)
}

// TestEncodeDecodeSumWithProofs tests EncodeSum and DecodeSum with input range validation
func TestEncodeDecodeSumWithProofs(t *testing.T) {
	//data
	inputValues := []int64{0, 10, 9}
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	expect := int64(0)
	for _, el := range inputValues {
		expect += el
	}

	//signatures needed to check the proof
	u := int64(2)
	l := int64(6)
	ps := []libdrynx.PublishSignature{libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))}

	//function call
	resultEncrypted, _, prf := libdrynxencoding.EncodeSumWithProofs(inputValues, pubKey, ps, l, u)
	result := libdrynxencoding.DecodeSum(*resultEncrypted, secKey)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[0]), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expect, result)
}
