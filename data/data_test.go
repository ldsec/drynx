package drynxdata_test

import (
	"github.com/lca1/drynx/data"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/obfuscation"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"testing"
)

func TestCreateRandomGoodTestData(t *testing.T) {

	keys := key.NewKeyPair(libunlynx.SuiTe)
	_, pubKey := keys.Private, keys.Public

	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, roster, _ := local.GenTree(5, true)

	nbrProofs := 4

	ranges := make([]*[]int64, nbrProofs)
	for i := range ranges {
		ranges[i] = &[]int64{16, 16}
	}

	ps := make([]*[]libdrynx.PublishSignatureBytes, len(roster.List))
	for i := range roster.List {
		temp := make([]libdrynx.PublishSignatureBytes, nbrProofs)
		for j := 0; j < nbrProofs; j++ {
			temp[j] = libdrynxrange.InitRangeProofSignature((*ranges[j])[0])
		}
		ps[i] = &temp
	}

	dv, err := drynxdata.CreateRandomGoodTestData(roster, pubKey, ps, ranges, nbrProofs)
	assert.NoError(t, err)

	for i := 0; i < nbrProofs; i++ {
		assert.True(t, libunlynxaggr.AggregationListProofVerification(*dv.ProofsAggregation[i], 1.0))
		assert.True(t, libunlynxkeyswitch.KeySwitchListProofVerification(*dv.ProofsKeySwitch[i], 1.0))
		assert.True(t, libdrynxobfuscation.ObfuscationListProofVerification(*dv.ProofsObfuscation[i], 1.0))
		assert.True(t, libunlynxshuffle.ShuffleProofVerification(*dv.ProofShuffle[i], roster.Aggregate))
		assert.True(t, libdrynxrange.RangeProofListVerification(*dv.ProofsRange[i], ranges, ps, roster.Aggregate, 1.0))
	}
}
