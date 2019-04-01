package protocols_test

/*import (
	"testing"
	"time"

	"github.com/lca1/drynx/protocols"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

var nbrNodesLoc = 5
var privLoc = make([]kyber.Scalar, nbrNodes)
var pubLoc = make([]kyber.Point, nbrNodes)
var groupPubLoc = libunlynx.SuiTe.Point().Null()
var groupSecLoc = libunlynx.SuiTe.Scalar().Zero()

var precomputesLoc = make([][]libunlynx.CipherVectorScalar, nbrNodes)

func TestShufflingLocal(t *testing.T) {
	defer log.AfterTest(t)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	log.TestOutput(testing.Verbose(), 3)

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("ShufflingLocalTest", NewShufflingLocalTest)
	_, _, tree := local.GenTree(nbrNodesLoc, true)
	defer local.CloseAll()

	rootInstance, _ := local.CreateProtocol("ShufflingLocalTest", tree)
	protocol := rootInstance.(*protocols.ShufflingLocalProtocol)

	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:

		for _, v := range encryptedResult {
			decryptedVAggr := libunlynx.DecryptIntVector(groupSecLoc, &v.AggregatingAttributes)
			log.Lvl1(decryptedVAggr)
			//decryptedVGrp := libunlynx.DecryptIntVector(groupSec, &v.GroupByEnc)
			//present := false
			/*for _, w := range mapi {
				decryptedWAggr := libunlynx.DecryptIntVector(groupSec, &w.AggregatingAttributes)
				decryptedWGrp := libunlynx.DecryptIntVector(groupSec, &w.GroupByEnc)
				if reflect.DeepEqual(decryptedWAggr, decryptedVAggr) && reflect.DeepEqual(decryptedWGrp, decryptedVGrp) {
					present = true
				}
			}*/
/*if !present {
	t.Error("ERROR")
}*/
/*log.Lvl1(v)
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewShufflingTest is a special purpose protocol constructor specific to tests.
func NewShufflingLocalTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	for i := 0; i < nbrNodesLoc; i++ {
		privLoc[i] = libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		pubLoc[i] = libunlynx.SuiTe.Point().Mul(privLoc[i], libunlynx.SuiTe.Point().Base())
		groupPubLoc.Add(groupPubLoc, pubLoc[i])
		groupSecLoc.Add(groupSecLoc, privLoc[i])
	}
	for i := 0; i < nbrNodesLoc; i++ {
		privBytes, _ := privLoc[i].MarshalBinary()
		precomputesLoc[i] = libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), groupPubLoc, libunlynx.SuiTe.XOF(privBytes), 4, 10)
	}
	aggregateKey := groupPubLoc

	//create data
	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse3 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse1
	mapi[1] = processResponse2
	mapi[2] = processResponse3
	mapi[3] = processResponse1

	log.Lvl2("Data before shuffling ", mapi)

	pi, err := protocols.NewShufflingLocalProtocol(tni)
	log.Lvl2(err)
	protocol := pi.(*protocols.ShufflingLocalProtocol)
	protocol.CollectiveKey = groupPubLoc
	protocol.Precomputed = precomputesLoc[tni.Index()]
	protocol.Proofs = 0
	protocol.TargetOfShuffle = &mapi

	return protocol, err
}*/
