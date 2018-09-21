package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestServerAggregationProofVerification(t *testing.T) {
	_, pub := libunlynx.GenKey()
	tab := []int64{1, 2, 3, 4, 5}
	ev := libunlynx.EncryptIntVector(pub, tab)
	evResult := libunlynx.NewCipherVector(len(*ev))
	evResult.Add(*ev, *ev)
	dpResponse1 := ResponseDPOneGroup{Group: "1", Data: *ev}
	dpResponse2 := ResponseDPOneGroup{Group: "2", Data: *ev}
	dpResponseResult1 := ResponseDPOneGroup{Group: "1", Data: *evResult}
	dpResponseResult2 := ResponseDPOneGroup{Group: "2", Data: *evResult}
	dpAggregated := ResponseAllDPs{Data: []ResponseDPOneGroup{dpResponseResult1, dpResponseResult2}}
	dpResponses := ResponseAllDPs{Data: []ResponseDPOneGroup{dpResponse1, dpResponse1, dpResponse2, dpResponse2}}
	proofs := ServerAggregationProofCreation(dpResponses, dpAggregated)
	// bytes conversion test
	proofBytes := proofs.ToBytes()
	proofs.FromBytes(proofBytes)

	assert.True(t, ServerAggregationProofVerification(proofs))
}
