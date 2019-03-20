package encoding_test

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncodeDecodeBit(t *testing.T) {
	//data
	var inputValues []bool
	inputValues = append(inputValues, false)
	inputValues = append(inputValues, true)
	inputValues = append(inputValues, false)

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	expectOr := encoding.LocalResultOR(inputValues)
	expectAnd := encoding.LocalResultAND(inputValues)

	var resultEncryptedOr *libunlynx.CipherText
	resultEncryptedOr, _ = encoding.EncodeBitOr(expectOr, pubKey)
	resultOr := encoding.DecodeBitOR(*resultEncryptedOr, secKey)

	var resultEncryptedAnd *libunlynx.CipherText
	resultEncryptedAnd, _ = encoding.EncodeBitAND(expectAnd, pubKey)
	resultAnd := encoding.DecodeBitAND(*resultEncryptedAnd, secKey)

	assert.Equal(t, expectOr, resultOr)
	assert.Equal(t, expectAnd, resultAnd)
}

func TestEncodeDecodeBitWithProofs(t *testing.T) {
	//Data
	var inputValues []bool
	inputValues = append(inputValues, false)
	inputValues = append(inputValues, true)
	inputValues = append(inputValues, false)

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//expected results
	expectOr := encoding.LocalResultOR(inputValues)
	expectAnd := encoding.LocalResultAND(inputValues)
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)
	ps := []libdrynx.PublishSignature{libdrynx.PublishSignatureBytesToPublishSignatures(libdrynx.InitRangeProofSignature(u))}

	resultEncryptedOr, _, prfOr := encoding.EncodeBitOrWithProof(expectOr, pubKey, ps, l, u)
	resultOr := encoding.DecodeBitOR(*resultEncryptedOr, secKey)

	resultEncryptedAnd, _, prfAnd := encoding.EncodeBitANDWithProof(expectAnd, pubKey, ps, l, u)
	resultAnd := encoding.DecodeBitAND(*resultEncryptedAnd, secKey)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prfOr), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expectOr, resultOr)

	assert.True(t, libdrynx.RangeProofVerification(libdrynx.CreatePredicateRangeProofForAllServ(prfAnd), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expectAnd, resultAnd)
}
