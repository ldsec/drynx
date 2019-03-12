package protocols_test

import (
	"reflect"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"github.com/lca1/drynx/protocols"
	"github.com/lca1/unlynx/lib"
)

var nbrNodes = 5
var priv = make([]kyber.Scalar, nbrNodes)
var pub = make([]kyber.Point, nbrNodes)
var groupPub = libunlynx.SuiTe.Point().Null()
var groupSec = libunlynx.SuiTe.Scalar().Zero()

var precomputes = make([][]libunlynx.CipherVectorScalar, nbrNodes)

func TestShuffling(t *testing.T) {
	defer log.AfterTest(t)
	local := onet.NewLocalTest(libunlynx.SuiTe)
	log.TestOutput(testing.Verbose(), 1)

	for i := 0; i < nbrNodes; i++ {
		priv[i] = libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		pub[i] = libunlynx.SuiTe.Point().Mul(priv[i], libunlynx.SuiTe.Point().Base())
		groupPub.Add(groupPub, pub[i])
		groupSec.Add(groupSec, priv[i])
	}
	for i := 0; i < nbrNodes; i++ {
		privBytes, _ := priv[i].MarshalBinary()
		precomputes[i] = libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), groupPub, libunlynx.SuiTe.XOF(privBytes), 4, 10)
	}
	aggregateKey := groupPub

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("ShufflingTest", NewShufflingTest)
	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()

	rootInstance, _ := local.CreateProtocol("ShufflingTest", tree)
	protocol := rootInstance.(*protocols.ShufflingProtocol)

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

	protocol.TargetOfShuffle = &mapi
	protocol.CollectiveKey = groupPub
	protocol.Proofs = 0

	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:

		for _, v := range encryptedResult {
			decryptedVAggr := libunlynx.DecryptIntVector(groupSec, &v.AggregatingAttributes)
			log.Lvl1(decryptedVAggr)
			decryptedVGrp := libunlynx.DecryptIntVector(groupSec, &v.GroupByEnc)
			present := false
			for _, w := range mapi {
				decryptedWAggr := libunlynx.DecryptIntVector(groupSec, &w.AggregatingAttributes)
				decryptedWGrp := libunlynx.DecryptIntVector(groupSec, &w.GroupByEnc)
				if reflect.DeepEqual(decryptedWAggr, decryptedVAggr) && reflect.DeepEqual(decryptedWGrp, decryptedVGrp) {
					present = true
				}
			}
			if !present {
				t.Error("ERROR")
			}
			log.Lvl1(v)
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewShufflingTest is a special purpose protocol constructor specific to tests.
func NewShufflingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocols.NewShufflingProtocol(tni)
	protocol := pi.(*protocols.ShufflingProtocol)
	protocol.CollectiveKey = groupPub
	protocol.Precomputed = precomputes[tni.Index()]
	protocol.Proofs = 0

	return protocol, err
}
