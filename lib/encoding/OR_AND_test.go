package encoding_test

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)


func TestEncodeDecodeBit(t *testing.T) {
	//data
	var inputValues []bool
	inputValues = append(inputValues, false)
	inputValues = append(inputValues, true)
	inputValues = append(inputValues, false)

	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	expect_OR := encoding.LocalResult_OR(inputValues)
	expect_AND := encoding.LocalResult_AND(inputValues)

	var resultEncrypted_OR *libunlynx.CipherText
	resultEncrypted_OR, _ = encoding.EncodeBit_OR(expect_OR, pubKey)
	result_OR := encoding.DecodeBit_OR(*resultEncrypted_OR, secKey)

	var resultEncrypted_AND *libunlynx.CipherText
	resultEncrypted_AND, _ = encoding.EncodeBit_AND(expect_AND, pubKey)
	result_AND := encoding.DecodeBit_AND(*resultEncrypted_AND, secKey)

	assert.Equal(t, expect_OR, result_OR)
	assert.Equal(t, expect_AND, result_AND)
}

func TestEncodeDecodeBitWithProofs(t *testing.T) {
	//Data
	var inputValues []bool
	inputValues = append(inputValues, false)
	inputValues = append(inputValues, true)
	inputValues = append(inputValues, false)

	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	expect_OR := encoding.LocalResult_OR(inputValues)
	expect_AND := encoding.LocalResult_AND(inputValues)
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)
	ps := []libdrynx.PublishSignature{libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u))}


	resultEncrypted_OR, _, prfOr := encoding.EncodeBit_ORWithProof(expect_OR, pubKey,  ps, l, u)
	result_OR := encoding.DecodeBit_OR(*resultEncrypted_OR, secKey)


	resultEncrypted_AND, _, prfAnd := encoding.EncodeBit_ANDWithProof(expect_AND, pubKey, ps, l, u)
	result_AND := encoding.DecodeBit_AND(*resultEncrypted_AND, secKey)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prfOr), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expect_OR, result_OR)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prfAnd), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expect_AND, result_AND)
}