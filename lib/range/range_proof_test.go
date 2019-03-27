package libdrynxrange_test

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/key"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRangeProofVerification(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	if !libdrynx.CurvePairingTest() {
		t.Skip("no pairing")
	}
	u := int64(2)
	l := int64(6)

	keys := key.NewKeyPair(libunlynx.SuiTe)
	P := keys.Public

	sig := make([]libdrynx.PublishSignature, 5)
	publishArgs := make([]libdrynxrange.RangeProof, 5)
	for i := 0; i < 5; i++ {
		sig[i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		encryption, r := libunlynx.EncryptIntGetR(P, int64(25))
		publishArgs[i] = libdrynxrange.CreatePredicateRangeProof(sig[i], u, l, int64(25), r, P, *encryption)
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)
	}

	publishArgs = make([]libdrynxrange.RangeProof, 5)
	for i := 0; i < 5; i++ {
		encryption, _ := libunlynx.EncryptIntGetR(P, int64(25))
		publishArgs[i] = libdrynxrange.CreatePredicateRangeProof(libdrynx.PublishSignature{}, 0, 0, 0, nil, nil, *encryption)
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)
		assert.True(t, libdrynxrange.RangeProofVerification(publishArgs[i], 0, 0, nil, nil))
	}
}

func TestOptimizedRangeProofVerification(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	if !libdrynx.CurvePairingTest() {
		t.Skip("no pairing")
	}
	u := int64(2)
	l := int64(1)

	keys := key.NewKeyPair(libunlynx.SuiTe)
	P := keys.Public

	sig := make([]libdrynx.PublishSignature, 5)
	//publishArgs := make([]libunlynx.RangeProof, 5)
	encryption, r := libunlynx.EncryptIntGetR(P, int64(1))
	for i := 0; i < 5; i++ {
		sig[i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)

	}
	cp := libdrynxrange.CreateProof{Sigs: sig, U: u, L: l, Secret: int64(1), R: r, CaPub: P, Cipher: *encryption}
	publishArgs := libdrynxrange.CreatePredicateRangeProofForAllServ(cp)
	//check when no proof --> u = 0 & l = 0
	// test bytes conversion
	publishArgsbytes := publishArgs.ToBytes()

	tmpProof := libdrynxrange.RangeProof{}
	tmpProof.FromBytes(publishArgsbytes)

	ys := make([]kyber.Point, 5)
	for i := 0; i < 5; i++ {
		ys[i] = sig[i].Public
	}

	assert.True(t, libdrynxrange.RangeProofVerification(publishArgs, u, l, ys, P))
}
