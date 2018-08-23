package lib

import (
	"github.com/dedis/kyber"
	"math"
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
)

// PublishedKSProof contains all infos about proofs for key switching
type PublishedKSProof struct {
	Proof []byte
	K     kyber.Point
	ViB   kyber.Point
	Ks2   kyber.Point
	RbNeg kyber.Point
	Q     kyber.Point
}

// PublishedKSProofBytes is the bytes' version of PublishedKSProof
type PublishedKSProofBytes struct {
	Proof         []byte
	KVibKs2RbnegQ []byte
}

// PublishedKSListProof is a list of PublishedKSProof
type PublishedKSListProof struct {
	Prs []PublishedKSProof
}

// PublishedKSListProof is the bytes' version of PublishedKSListProof
type PublishedKSListProofBytes struct {
	PrsB []PublishedKSProofBytes
}

// ToBytes converts PublishedKSProof to bytes
func (pksp *PublishedKSProof) ToBytes() PublishedKSProofBytes {
	popb := PublishedKSProofBytes{}
	popb.Proof = pksp.Proof
	popb.KVibKs2RbnegQ = libunlynx.AbstractPointsToBytes([]kyber.Point{pksp.K, pksp.ViB, pksp.Ks2, pksp.RbNeg, pksp.Q})
	return popb
}

// FromBytes converts back bytes to PublishedKSProof
func (pksp *PublishedKSProof) FromBytes(pkspb PublishedKSProofBytes) {
	pksp.Proof = pkspb.Proof
	KVibKs2RbnegQ := libunlynx.BytesToAbstractPoints(pkspb.KVibKs2RbnegQ)
	pksp.K = KVibKs2RbnegQ[0]
	pksp.ViB = KVibKs2RbnegQ[1]
	pksp.Ks2 = KVibKs2RbnegQ[2]
	pksp.RbNeg = KVibKs2RbnegQ[3]
	pksp.Q = KVibKs2RbnegQ[4]
}

// ToBytes converts PublishedKSListProof to bytes
func (pkslp *PublishedKSListProof) ToBytes() PublishedKSListProofBytes {
	pkslpb := PublishedKSListProofBytes{}

	prsB := make([]PublishedKSProofBytes, len(pkslp.Prs))
	wg := libunlynx.StartParallelize(len(pkslp.Prs))
	for i, pksp := range pkslp.Prs {
		go func(index int, pksp PublishedKSProof) {
			defer wg.Done()
			prsB[index] = pksp.ToBytes()
		}(i, pksp)
	}
	libunlynx.EndParallelize(wg)
	pkslpb.PrsB = prsB
	return pkslpb
}

//FromBytes converts bytes back to PublishedKSListProof
func (pkslp *PublishedKSListProof) FromBytes(pkslpb PublishedKSListProofBytes) {
	prs := make([]PublishedKSProof, len(pkslpb.PrsB))
	wg := libunlynx.StartParallelize(len(pkslpb.PrsB))
	for i, pkspb := range pkslpb.PrsB {
		go func(index int, pkspb PublishedKSProofBytes) {
			defer wg.Done()
			tmp := PublishedKSProof{}
			tmp.FromBytes(pkspb)
			prs[index] = tmp
		}(i, pkspb)
	}
	libunlynx.EndParallelize(wg)
	pkslp.Prs = prs
}

func createPredicateNewKeySwitch() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("viB", "vi", "B")
	log2 := proof.Rep("K", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("ks2", "k", "rBNeg", "vi", "Q")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	predicate = proof.And(and)

	return
}

// KeySwitchProofCreation creates a key switch proof for one ciphertext
func KeySwitchProofCreation(K, viB, ks2, rBNeg, Q kyber.Point, vi, k kyber.Scalar) PublishedKSProof {
	predicate := createPredicateNewKeySwitch()
	sval := map[string]kyber.Scalar{"vi": vi, "k": k}
	pval := map[string]kyber.Point{"K": K, "viB": viB, "ks2": ks2, "rBNeg": rBNeg, "Q": Q}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedKSProof{Proof: Proof, K: K, ViB: viB, Ks2: ks2, RbNeg: rBNeg, Q: Q}
}

// KeySwitchListProofCreation creates a list of key switch proofs (multiple ciphertexts)
func KeySwitchListProofCreation(K, Q kyber.Point, k kyber.Scalar, length int, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) PublishedKSListProof {
	viBs := make([]kyber.Point, length)
	wg := libunlynx.StartParallelize(length)
	for i, v := range vis {
		go func(i int, v kyber.Scalar) {
			defer wg.Done()
			viBs[i] = libunlynx.SuiTe.Point().Mul(v, libunlynx.SuiTe.Point().Base())
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	wg = libunlynx.StartParallelize(len(viBs))
	plop := PublishedKSListProof{}
	plop.Prs = make([]PublishedKSProof, len(viBs))
	for i, v := range viBs {
		go func(i int, v kyber.Point) {
			defer wg.Done()
			plop.Prs[i] = KeySwitchProofCreation(K, viBs[i], ks2s[i], rBNegs[i], Q, vis[i], k)
		}(i, v)

	}
	libunlynx.EndParallelize(wg)

	return plop
}

// KeySwitchProofVerification verifies a key switch proof for one ciphertext
func KeySwitchProofVerification(pop PublishedKSProof) bool {
	predicate := createPredicateNewKeySwitch()
	pval := map[string]kyber.Point{"K": pop.K, "viB": pop.ViB, "ks2": pop.Ks2, "rBNeg": pop.RbNeg, "Q": pop.Q}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)

	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, pop.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// KeySwitchListProofVerification verifies a list of key switch proof, if one is worng, returns false
func KeySwitchListProofVerification(pkslp PublishedKSListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pkslp.Prs))))
	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedKSProof) {
			defer wg.Done()
			results[i] = KeySwitchProofVerification(v)
		}(i, pkslp.Prs[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}
