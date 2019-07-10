package protocols_test

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"testing"
	"time"

	"github.com/lca1/drynx/protocols"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

var priv1 kyber.Scalar
var pub1 kyber.Point

//TestObfuscation tests collective obfuscation protocol
func TestObfuscation(t *testing.T) {

	keys := key.NewKeyPair(libunlynx.SuiTe)
	priv1, pub1 = keys.Private, keys.Public

	log.SetDebugVisible(2)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	// You must register this protocol before creating the servers
	if _, err := onet.GlobalProtocolRegister("ObfuscationTest", NewObfuscationTest); err != nil {
		log.Fatal("Failed to register the <ObfuscationTest> protocol:", err)
	}

	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("ObfuscationTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := p.(*protocols.ObfuscationProtocol)
	/*tmp := *libunlynx.EncryptIntVector(pub, []int64{0, 1, 2})
	mu := sync.Mutex{}
	mu.Lock()
	protocol.ToObfuscateData = tmp
	//protocol.Proofs = 0
	mu.Unlock()*/

	//run protocol
	go func() {
		if err := protocol.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expresult := []int64{0, 1, 1}
	result := make([]int64, 3)
	select {
	case encryptedResult := <-feedback:
		for i, v := range encryptedResult {
			result[i] = libunlynx.DecryptCheckZero(priv1, v)
		}

		assert.Equal(t, expresult, result)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewObfuscationTest is a test specific protocol instance constructor that injects test data.
func NewObfuscationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pi, err := protocols.NewObfuscationProtocol(tni)
	protocol := pi.(*protocols.ObfuscationProtocol)
	if tni.IsRoot() {
		protocol.ToObfuscateData = *libunlynx.EncryptIntVector(pub1, []int64{0, 1, 2})
	}
	protocol.Proofs = 0
	return protocol, err
}
