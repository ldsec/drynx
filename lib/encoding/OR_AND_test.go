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
	expectOr := libdrynxencoding.LocalResultOR(inputValues)
	expectAnd := libdrynxencoding.LocalResultAND(inputValues)

	var resultEncryptedOr *libunlynx.CipherText
	resultEncryptedOr, _ = libdrynxencoding.EncodeBitOr(expectOr, pubKey)
	resultOr := libdrynxencoding.DecodeBitOR(*resultEncryptedOr, secKey)

	var resultEncryptedAnd *libunlynx.CipherText
	resultEncryptedAnd, _ = libdrynxencoding.EncodeBitAND(expectAnd, pubKey)
	resultAnd := libdrynxencoding.DecodeBitAND(*resultEncryptedAnd, secKey)

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
	expectOr := libdrynxencoding.LocalResultOR(inputValues)
	expectAnd := libdrynxencoding.LocalResultAND(inputValues)
	//signatures needed to check the proof
	u := int64(2)
	l := int64(1)
	ps := []libdrynx.PublishSignature{libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))}

	resultEncryptedOr, _, prfOr := libdrynxencoding.EncodeBitOrWithProof(expectOr, pubKey, ps, l, u)
	resultOr := libdrynxencoding.DecodeBitOR(*resultEncryptedOr, secKey)

	resultEncryptedAnd, _, prfAnd := libdrynxencoding.EncodeBitANDWithProof(expectAnd, pubKey, ps, l, u)
	resultAnd := libdrynxencoding.DecodeBitAND(*resultEncryptedAnd, secKey)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prfOr), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expectOr, resultOr)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prfAnd), u, l, []kyber.Point{ps[0].Public}, pubKey))
	assert.Equal(t, expectAnd, resultAnd)
}
