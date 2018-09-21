package protocols_test

import (
	"testing"
	"time"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/protocols"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

//var obfuscation = true

//TestCollectiveAggregation tests collective aggregation protocol
func TestObfuscation(t *testing.T) {
	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("ObfuscationTest", NewObfuscationTest)

	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("ObfuscationTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	priv, pub := libunlynx.GenKey()
	protocol := p.(*protocols.ObfuscationProtocol)
	protocol.ToObfuscateData = *libunlynx.EncryptIntVector(pub, []int64{0, 1, 2})
	protocol.Proofs = 0

	//run protocol
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expresult := []int64{0, 1, 1}
	result := make([]int64, 3)
	select {
	case encryptedResult := <-feedback:
		for i, v := range encryptedResult {
			result[i] = libunlynx.DecryptCheckZero(priv, v)
		}

		assert.Equal(t, expresult, result)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewCollectiveAggregationTest is a test specific protocol instance constructor that injects test data.
func NewObfuscationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pi, err := protocols.NewObfuscationProtocol(tni)
	protocol := pi.(*protocols.ObfuscationProtocol)

	protocol.Proofs = 0
	//protocol.Obfuscation = obfuscation
	return protocol, err
}
