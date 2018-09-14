package protocols_test

import (
	"testing"
	"time"

	"reflect"

	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/protocols"
)

func TestCtks(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	onet.GlobalProtocolRegister("CtksTest", NewCtksTest)
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("CtksTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := rootInstance.(*protocols.KeySwitchingProtocol)
	aggregateKey := entityList.Aggregate
	log.LLvl1("AGGREGATE ", aggregateKey)

	//create data
	expRes1 := []int64{1, 2, 3, 6}
	//testCipherVectGroup1 := *libunlynx.EncryptIntVector(aggregateKey, expRes1)
	testCipherVect1 := *libunlynx.EncryptIntVector(aggregateKey, expRes1)

	expRes2 := []int64{7, 8, 9, 7}
	//testCipherVectGroup2 := *libunlynx.EncryptIntVector(aggregateKey, expRes2)
	testCipherVect2 := *libunlynx.EncryptIntVector(aggregateKey, expRes2)

	//var tabi []libunlynx.CipherText
	tabi := make(libunlynx.CipherVector, 0)
	tabi = append(tabi, testCipherVect1...)
	tabi = append(tabi, testCipherVect2...)
	log.LLvl1(tabi)
	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	clientPublic := libunlynx.SuiTe.Point().Mul(clientPrivate, libunlynx.SuiTe.Point().Base())

	//protocol
	protocol.TargetOfSwitch = &tabi
	protocol.TargetPublicKey = &clientPublic
	protocol.Proofs = 0
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		cv1 := encryptedResult
		res := libunlynx.DecryptIntVector(clientPrivate, &cv1)
		//resGrp := libunlynx.DecryptIntVector(clientPrivate, &cv1.GroupByEnc)
		log.Lvl2("Received results (attributes) ", res)
		//log.Lvl1("Received results (groups) ", resGrp)
		/*cv2 := encryptedResult[1]
		res1 := libunlynx.DecryptIntVector(clientPrivate, &cv2.AggregatingAttributes)
		resGrp1 := libunlynx.DecryptIntVector(clientPrivate, &cv2.GroupByEnc)
		log.Lvl1("Received results (attributes) ", res1)
		log.Lvl1("Received results (groups) ", resGrp1)*/

		if !reflect.DeepEqual(res, append(expRes1, expRes2...)) {
			t.Fatal("Wrong results, expected", expRes1, "but got", res)
		} else {
			t.Log("Good results")
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewKeySwitchingTest is a special purpose protocol constructor specific to tests.
func NewCtksTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocols.NewKeySwitchingProtocol(tni)
	protocol := pi.(*protocols.KeySwitchingProtocol)
	protocol.Proofs = 0

	return protocol, err
}
