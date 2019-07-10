package drynxdata

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/obfuscation"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/shuffle"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
)

// DataToVerify contains the proofs to be verified by the skipchain CA
type DataToVerify struct {
	ProofsRange       []*libdrynxrange.RangeProofList
	ProofsAggregation []*libunlynxaggr.PublishedAggregationListProof
	ProofsObfuscation []*libdrynxobfuscation.PublishedListObfuscationProof
	ProofsKeySwitch   []*libunlynxkeyswitch.PublishedKSListProof
	ProofShuffle      []*libunlynxshuffle.PublishedShufflingProof
}

//CreateRandomGoodTestData only creates valid proofs
func CreateRandomGoodTestData(roster *onet.Roster, pub kyber.Point, ps []*[]libdrynx.PublishSignatureBytes, ranges []*[]int64, nbrProofs int) DataToVerify {
	var secKey = bn256.NewSuiteG1().Scalar().Pick(random.New())
	var entityPub = bn256.NewSuiteG1().Point().Mul(secKey, bn256.NewSuiteG1().Point().Base())
	var tab1 = []int64{1, 2, 3, 6}
	var tab2 = []int64{2, 4, 8, 6}

	result := DataToVerify{}
	result.ProofsKeySwitch = make([]*libunlynxkeyswitch.PublishedKSListProof, nbrProofs)
	result.ProofsRange = make([]*libdrynxrange.RangeProofList, nbrProofs)
	result.ProofsAggregation = make([]*libunlynxaggr.PublishedAggregationListProof, nbrProofs)
	result.ProofsObfuscation = make([]*libdrynxobfuscation.PublishedListObfuscationProof, nbrProofs)
	result.ProofShuffle = make([]*libunlynxshuffle.PublishedShufflingProof, nbrProofs)

	//Fill Aggregation with good proofs
	for i := range result.ProofsAggregation {
		tab := []int64{1, 2, 3, 4, 5}
		ev := libunlynx.EncryptIntVector(roster.Aggregate, tab)
		evresult := ev.Acum()
		listProofs := libunlynxaggr.AggregationListProofCreation([]libunlynx.CipherVector{*ev, *ev}, libunlynx.CipherVector{evresult, evresult})
		result.ProofsAggregation[i] = &listProofs
	}

	for i := range result.ProofsObfuscation {
		tab := []int64{1, 2}
		e := libunlynx.EncryptIntVector(roster.Aggregate, tab)
		obfFactor := libunlynx.SuiTe.Scalar().Pick(random.New())
		newE1 := libunlynx.CipherText{}
		newE1.MulCipherTextbyScalar((*e)[0], obfFactor)
		newE2 := libunlynx.CipherText{}
		newE2.MulCipherTextbyScalar((*e)[1], obfFactor)
		proof := libdrynxobfuscation.ObfuscationListProofCreation(*e, libunlynx.CipherVector{newE1, newE2}, []kyber.Scalar{obfFactor, obfFactor})
		result.ProofsObfuscation[i] = &proof
	}

	for i := range result.ProofShuffle {
		testCipherVect1 := *libunlynx.EncryptIntVector(roster.Aggregate, tab1)
		testCipherVect2 := *libunlynx.EncryptIntVector(roster.Aggregate, tab2)

		responses := make([]libunlynx.CipherVector, 0)
		responses = append(responses, testCipherVect1, testCipherVect2)

		responsesShuffled, pi, beta := libunlynxshuffle.ShuffleSequence(responses, libunlynx.SuiTe.Point().Base(), roster.Aggregate, nil)
		prf, _ := libunlynxshuffle.ShuffleProofCreation(responses, responsesShuffled, libunlynx.SuiTe.Point().Base(), roster.Aggregate, beta, pi)
		result.ProofShuffle[i] = &prf
	}

	for i := range result.ProofsKeySwitch {
		cipher := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 2})
		initialTab := make([]kyber.Point, 2)
		for i, v := range *cipher {
			initialTab[i] = v.K
		}

		_, ks2s, rBNegs, vis := libunlynxkeyswitch.KeySwitchSequence(pub, initialTab, secKey)
		pkslp, _ := libunlynxkeyswitch.KeySwitchListProofCreation(entityPub, pub, secKey, ks2s, rBNegs, vis)

		result.ProofsKeySwitch[i] = &pkslp
	}

	for i := range result.ProofsRange {

		encryption, r := libunlynx.EncryptIntGetR(roster.Aggregate, int64(25))

		// read the signatures needed to compute the range proofs
		signatures := make([][]libdrynx.PublishSignature, len(roster.List))
		for i := 0; i < len(roster.List); i++ {
			signatures[i] = make([]libdrynx.PublishSignature, len(ranges))
			for j := 0; j < len(ranges); j++ {
				signatures[i][j] = libdrynxrange.PublishSignatureBytesToPublishSignatures((*ps[i])[j])
			}
		}

		cp := libdrynxrange.CreateProof{Sigs: libdrynxrange.ReadColumn(signatures, 0), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cp1 := libdrynxrange.CreateProof{Sigs: libdrynxrange.ReadColumn(signatures, 1), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cps := []libdrynxrange.CreateProof{cp, cp1}
		rps := libdrynxrange.RangeProofList{Data: libdrynxrange.CreatePredicateRangeProofListForAllServers(cps)}
		result.ProofsRange[i] = &rps
	}

	return result
}
