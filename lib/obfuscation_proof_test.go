package libdrynx

import (
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestObfuscationProofVerification(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pub, sec := keys.Public, keys.Private

	tab := int64(2)
	ev := libunlynx.EncryptInt(pub, tab)
	obfuscationFactor := sec
	evo := libunlynx.CipherText{K: libunlynx.SuiTe.Point().Mul(obfuscationFactor, ev.K), C: libunlynx.SuiTe.Point().Mul(obfuscationFactor, ev.C)}
	op := ObfuscationProofCreation(*ev, evo, obfuscationFactor)
	assert.True(t, ObfuscationProofVerification(op))

	opb := op.ToBytes()
	nop := PublishedObfuscationProof{}
	nop.FromBytes(opb)
	assert.True(t, ObfuscationProofVerification(nop))

	lop := PublishedListObfuscationProof{Prs: []PublishedObfuscationProof{op, nop}}
	assert.True(t, ObfuscationListProofVerification(lop, 1))

	op = ObfuscationProofCreation(*ev, evo, libunlynx.SuiTe.Scalar().One())
	assert.False(t, ObfuscationProofVerification(op))
}
