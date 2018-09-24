package libdrynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"math"
)

// PublishedObfuscationProof contains all infos about proofs for addition in det, tagging of one element
type PublishedObfuscationProof struct {
	C     libunlynx.CipherText
	Co    libunlynx.CipherText
	Proof []byte
}

// PublishedObfuscationProofBytes is the bytes' version of PublishedObfuscationProof
type PublishedObfuscationProofBytes struct {
	C     []byte
	Co    []byte
	Proof []byte
}

// PublishedListObfuscationProof contains all infos about proofs for addition in det, tagging of one element
type PublishedListObfuscationProof struct {
	Prs []PublishedObfuscationProof
}

// PublishedListObfuscationProofBytes is the bytes' version of PublishedListObfuscationProof
type PublishedListObfuscationProofBytes struct {
	PrsB []PublishedObfuscationProofBytes
}

// createPredicateObfuscation creates predicate for obfuscation proof
func createPredicateObfuscation() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("co1", "s", "c1")
	log2 := proof.Rep("co2", "s", "c2")
	and := proof.And(log1, log2)
	predicate = proof.And(and)

	return predicate
}

// ObfuscationProofCreation creates proof for obfuscation of ciphertext
func ObfuscationProofCreation(c, co libunlynx.CipherText, s kyber.Scalar) PublishedObfuscationProof {
	predicate := createPredicateObfuscation()
	sval := map[string]kyber.Scalar{"s": s}
	pval := map[string]kyber.Point{"c1": c.K, "c2": c.C, "co1": co.K, "co2": co.C}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedObfuscationProof{Proof: Proof, C: c, Co: co}
}

// ObfuscationListProofCreation creates proofs for obfuscation of multiple ciphertext
func ObfuscationListProofCreation(c, co []libunlynx.CipherText, s []kyber.Scalar) PublishedListObfuscationProof {
	wg := libunlynx.StartParallelize(len(c))
	plop := PublishedListObfuscationProof{}
	plop.Prs = make([]PublishedObfuscationProof, len(s))

	for i, v := range s {
		go func(i int, v kyber.Scalar) {
			defer wg.Done()
			plop.Prs[i] = ObfuscationProofCreation(c[i], co[i], v)
		}(i, v)

	}
	libunlynx.EndParallelize(wg)

	return plop
}

// ObfuscationProofVerification checks an obfuscation proof
func ObfuscationProofVerification(pop PublishedObfuscationProof) bool {
	predicate := createPredicateObfuscation()
	pval := map[string]kyber.Point{"c1": pop.C.K, "c2": pop.C.C, "co1": pop.Co.K, "co2": pop.Co.C}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)

	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, pop.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// ObfuscationListProofVerification checks a list of obfuscation proofs
func ObfuscationListProofVerification(plop PublishedListObfuscationProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(plop.Prs))))
	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedObfuscationProof) {
			defer wg.Done()
			results[i] = ObfuscationProofVerification(v)
		}(i, plop.Prs[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// BYTES CONVERSION

//ToBytes converts PublishedObfuscationProof to its bytes' version
func (pop *PublishedObfuscationProof) ToBytes() PublishedObfuscationProofBytes {
	popb := PublishedObfuscationProofBytes{}
	popb.Proof = pop.Proof
	popb.C = pop.C.ToBytes()
	popb.Co = pop.Co.ToBytes()
	return popb
}

//FromBytes converts bytes back to PublishedObfuscationProof
func (pop *PublishedObfuscationProof) FromBytes(popb PublishedObfuscationProofBytes) {
	pop.Proof = popb.Proof
	pop.C.FromBytes(popb.C)
	pop.Co.FromBytes(popb.Co)
}

//ToBytes converts PublishedListObfuscationProof to bytes
func (pop *PublishedListObfuscationProof) ToBytes() PublishedListObfuscationProofBytes {

	plopb := PublishedListObfuscationProofBytes{}
	popB := make([]PublishedObfuscationProofBytes, len(pop.Prs))
	wg := libunlynx.StartParallelize(len(pop.Prs))
	for i, plop := range pop.Prs {
		go func(index int, plop PublishedObfuscationProof) {
			defer wg.Done()
			popB[index] = plop.ToBytes()
		}(i, plop)
	}
	libunlynx.EndParallelize(wg)

	plopb.PrsB = popB
	return plopb
}

//FromBytes converts bytes back to PublishedListObfuscationProof
func (pop *PublishedListObfuscationProof) FromBytes(plopb PublishedListObfuscationProofBytes) {
	prs := make([]PublishedObfuscationProof, len(plopb.PrsB))
	wg := libunlynx.StartParallelize(len(plopb.PrsB))
	for i, popb := range plopb.PrsB {
		go func(index int, popb PublishedObfuscationProofBytes) {
			defer wg.Done()
			tmp := PublishedObfuscationProof{}
			tmp.FromBytes(popb)
			prs[index] = tmp
		}(i, popb)
	}
	libunlynx.EndParallelize(wg)
	pop.Prs = prs
}
