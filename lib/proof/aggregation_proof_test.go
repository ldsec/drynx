package proof_test

import (
	"testing"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"github.com/dedis/onet/log"
	"github.com/lca1/drynx/lib/proof"
)

func TestServerAggregationProofVerification(t *testing.T) {
	sec, pub := libunlynx.GenKey()
	tab := []int64{1, 2, 3, 4, 5}
	ev := libunlynx.EncryptIntVector(pub, tab)
	log.LLvl1(*ev)
	evresult := libunlynx.NewCipherVector(len(*ev))
	evresult.Add(*ev, *ev)
	log.LLvl1(libunlynx.DecryptIntVector(sec, evresult))
	dpResponse1 := libunlynx.ResponseDPOneGroup{Group: "1", Data: *ev}
	dpResponse2 := libunlynx.ResponseDPOneGroup{Group: "2", Data: *ev}
	dpResponseResult1 := libunlynx.ResponseDPOneGroup{Group: "1", Data: *evresult}
	dpResponseResult2 := libunlynx.ResponseDPOneGroup{Group: "2", Data: *evresult}
	log.LLvl1(*evresult)
	dpAggregated := libunlynx.ResponseAllDPs{Data: []libunlynx.ResponseDPOneGroup{dpResponseResult1, dpResponseResult2}}
	dpResponses := libunlynx.ResponseAllDPs{Data: []libunlynx.ResponseDPOneGroup{dpResponse1, dpResponse1, dpResponse2, dpResponse2}}
	proofs := proof.ServerAggregationProofCreation(dpResponses, dpAggregated)
	// bytes conversion test
	proofBytes := proofs.ToBytes()
	proofs.FromBytes(proofBytes)

	assert.True(t, proof.ServerAggregationProofVerification(proofs))
}