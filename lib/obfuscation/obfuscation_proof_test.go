package libdrynxobfuscation_test

import (
	"github.com/lca1/drynx/lib/obfuscation"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/key"
	"testing"
)

func TestObfuscationProofVerification(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pub, sec := keys.Public, keys.Private

	tab := int64(2)
	ev := libunlynx.EncryptInt(pub, tab)
	obfuscationFactor := sec
	evo := libunlynx.CipherText{K: libunlynx.SuiTe.Point().Mul(obfuscationFactor, ev.K), C: libunlynx.SuiTe.Point().Mul(obfuscationFactor, ev.C)}
	op := libdrynxobfuscation.ObfuscationProofCreation(*ev, evo, obfuscationFactor)
	assert.True(t, libdrynxobfuscation.ObfuscationProofVerification(op))

	opb := op.ToBytes()
	nop := libdrynxobfuscation.PublishedObfuscationProof{}
	nop.FromBytes(opb)
	assert.True(t, libdrynxobfuscation.ObfuscationProofVerification(nop))

	lop := libdrynxobfuscation.PublishedListObfuscationProof{Prs: []libdrynxobfuscation.PublishedObfuscationProof{op, nop}}
	assert.True(t, libdrynxobfuscation.ObfuscationListProofVerification(lop, 1))

	op = libdrynxobfuscation.ObfuscationProofCreation(*ev, evo, libunlynx.SuiTe.Scalar().One())
	assert.False(t, libdrynxobfuscation.ObfuscationProofVerification(op))
}
