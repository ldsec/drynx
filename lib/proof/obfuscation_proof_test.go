package proof_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/lca1/drynx/lib/proof"
)

func TestObfuscationProofVerification(t *testing.T) {
	sec, pub := libunlynx.GenKey()
	tab := int64(2)
	ev := libunlynx.EncryptInt(pub, tab)
	obfuscationFactor := sec
	evo := libunlynx.CipherText{libunlynx.SuiTe.Point().Mul(obfuscationFactor,ev.K), libunlynx.SuiTe.Point().Mul(obfuscationFactor,ev.C)}
	op := proof.ObfuscationProofCreation(*ev, evo, obfuscationFactor)
	assert.True(t, proof.ObfuscationProofVerification(op))

	opb := op.ToBytes()
	nop := proof.PublishedObfuscationProof{}
	nop.FromBytes(opb)
	assert.True(t, proof.ObfuscationProofVerification(nop))

	lop := proof.PublishedListObfuscationProof{Prs:[]proof.PublishedObfuscationProof{op, nop}}
	assert.True(t, proof.ObfuscationListProofVerification(lop, 1))

	op = proof.ObfuscationProofCreation(*ev, evo, libunlynx.SuiTe.Scalar().One())
	assert.False(t, proof.ObfuscationProofVerification(op))
}