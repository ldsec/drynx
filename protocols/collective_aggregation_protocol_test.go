package protocols

import (
	"reflect"
	"testing"
	"time"

	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
)

var clientPrivate = bn256.NewSuiteG1().Scalar().Pick(random.New())
var clientPublic = bn256.NewSuiteG1().Point().Mul(clientPrivate, bn256.NewSuiteG1().Point().Base())
var grpattr1 = libunlynx.DeterministCipherText{Point: bn256.NewSuiteG1().Point().Base()}
var grpattr2 = libunlynx.DeterministCipherText{Point: bn256.NewSuiteG1().Point().Null()}
var groupingAttrA = libunlynx.DeterministCipherVector{grpattr1, grpattr1}
var groupingAttrAkey = libunlynx.GroupingKey("A") //groupingAttrA.Key()
var groupingAttrB = libunlynx.DeterministCipherVector{grpattr2, grpattr2}
var groupingAttrBkey = libunlynx.GroupingKey("B") //groupingAttrB.Key()
var groupingAttrC = libunlynx.DeterministCipherVector{grpattr1, grpattr2}
var groupingAttrCkey = libunlynx.GroupingKey("C") //groupingAttrC.Key()

//TestCollectiveAggregation tests collective aggregation protocol
func TestCollectiveAggregation(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("CollectiveAggregationTest", NewCollectiveAggregationTest)
	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("CollectiveAggregationTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := p.(*CollectiveAggregationProtocol)

	//run protocol
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	feedback := protocol.FeedbackChannel

	//verify results
	expectedGroups := map[libunlynx.GroupingKey][]int64{groupingAttrAkey: {1, 1},
		groupingAttrBkey: {1, 2},
		groupingAttrCkey: {3, 3}}

	expectedResults := map[libunlynx.GroupingKey][]int64{groupingAttrAkey: {3, 5, 7, 9, 11},
		groupingAttrBkey: {1, 2, 3, 4, 5},
		groupingAttrCkey: {1, 1, 1, 1, 1}}

	select {
	case encryptedResult := <-feedback:
		log.Lvl1("Received results:")
		resultData := make(map[libunlynx.GroupingKey][]int64)
		for k, v := range encryptedResult.GroupedData {
			resultData[k] = libunlynx.DecryptIntVector(clientPrivate, &v.AggregatingAttributes)
			log.Lvl1(k, resultData[k])

		}
		for k, v1 := range expectedGroups {
			if v2, ok := encryptedResult.GroupedData[k]; ok {
				assert.True(t, ok)
				_ = v1
				_ = v2
				assert.True(t, reflect.DeepEqual(v1, libunlynx.DecryptIntVector(clientPrivate, &v2.GroupByEnc)))

				delete(encryptedResult.GroupedData, k)
			}
		}
		assert.Empty(t, encryptedResult.GroupedData)
		assert.Equal(t, expectedResults, resultData)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewCollectiveAggregationTest is a test specific protocol instance constructor that injects test data.
func NewCollectiveAggregationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := NewCollectiveAggregationProtocol(tni)
	protocol := pi.(*CollectiveAggregationProtocol)

	testCVMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)

	switch tni.Index() {
	case 0:
		testCVMap[groupingAttrAkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
		testCVMap[groupingAttrBkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 0, 0, 0, 0})}
	case 1:
		testCVMap[groupingAttrBkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 2:
		testCVMap[groupingAttrAkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1, 1, 1, 1})}
	case 9:
		testCVMap[groupingAttrCkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 0, 1, 0, 1})}
		testCVMap[groupingAttrAkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 1}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{1, 2, 3, 4, 5})}
	case 5:
		testCVMap[groupingAttrCkey] = libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(clientPublic, []int64{3, 3}), AggregatingAttributes: *libunlynx.EncryptIntVector(clientPublic, []int64{0, 1, 0, 1, 0})}

	default:
	}
	protocol.GroupedData = &testCVMap
	//protocol.Obfuscation = obfuscation
	return protocol, err
}
