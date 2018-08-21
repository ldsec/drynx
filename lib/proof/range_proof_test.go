package proof_test

import (
	"testing"
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
	"github.com/lca1/drynx/lib/proof"
)

func TestRangeProofVerification(t *testing.T) {
	if !libunlynx.CurvePairingTest() {
		t.Skip("no pairing")
	}
	u := int64(2)
	l := int64(6)
	_, P := libunlynx.GenKey()

	sig := make([]proof.PublishSignature, 5)
	publishArgs := make([]proof.RangeProof, 5)
	for i := 0; i < 5; i++ {
		sig[i] = proof.PublishSignatureBytesToPublishSignatures(proof.InitRangeProofSignature(u))
		encryption, r := libunlynx.EncryptIntGetR(P, int64(25))
		publishArgs[i] = proof.CreatePredicateRangeProof(sig[i], u, l, int64(25), r, P, *encryption)
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)
		log.LLvl1(proof.RangeProofVerification(publishArgs[i], u, l, []kyber.Point{sig[i].Public}, P))
	}

	publishArgs = make([]proof.RangeProof, 5)
	for i := 0; i < 5; i++ {
		encryption, _ := libunlynx.EncryptIntGetR(P, int64(25))
		publishArgs[i] = proof.CreatePredicateRangeProof(proof.PublishSignature{}, 0, 0, 0, nil, nil, *encryption)
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)
		log.LLvl1(proof.RangeProofVerification(publishArgs[i], 0, 0, nil, nil))
	}
}

func TestOptimizedRangeProofVerification(t *testing.T) {
	//aScalar := libunlynx.SuiTe
	//chimera := libunlynx.ChimeraSuite{}
	log.LLvl1(libunlynx.SuiTe.String())
	if !libunlynx.CurvePairingTest() {
		t.Skip("no pairing")
	}
	u := int64(2)
	l := int64(1)
	_, P := libunlynx.GenKey()

	sig := make([]proof.PublishSignature, 5)
	//publishArgs := make([]libunlynx.RangeProof, 5)
	encryption, r := libunlynx.EncryptIntGetR(P, int64(1))
	for i := 0; i < 5; i++ {
		sig[i] = proof.PublishSignatureBytesToPublishSignatures(proof.InitRangeProofSignature(u))
		//publishArgsFalse := lib.CreatePredicateRangeProof(sig[i],u,l,int64(65),P)

	}
	cp := proof.CreateProof{Sigs: sig, U: u, L: l, Secret: int64(25), R: r, CaPub: P, Cipher: *encryption}
	publishArgs := proof.CreatePredicateRangeProofForAllServ(cp)
	//check when no proof --> u = 0 & l = 0
	// test bytes conversion
	publishArgsbytes := publishArgs.ToBytes()
	tmpProof := proof.RangeProof{}
	tmpProof.FromBytes(publishArgsbytes)

	ys := make([]kyber.Point, 5)
	for i := 0; i < 5; i++ {
		ys[i] = sig[i].Public
	}

	log.LLvl1(proof.RangeProofVerification(tmpProof, u, l, ys, P))

}
