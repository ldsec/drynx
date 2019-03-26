package protocols

import (
	"github.com/coreos/bbolt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/stretchr/testify/assert"
	"gopkg.in/satori/go.uuid.v1"
	"os"
	"strconv"
	"sync"
	"testing"
)

type nodeTools struct {
	request     *concurrent.ConcurrentMap
	dataOfBlock *concurrent.ConcurrentMap
	dbPath      string
	db          *bbolt.DB
	mutex       *sync.Mutex
}

var nodeToolsMap map[string]*nodeTools
var testSQ libdrynx.SurveyQuery
var sharedBMChannel chan map[string]int64
var sharedBMChannelToTerminate chan struct{}

//TestProofCollectionProtocol tests collective aggregation protocol
func TestProofCollectionProtocol(t *testing.T) {
	network.RegisterMessage(libdrynx.GetLatestBlock{})
	network.RegisterMessage(libdrynx.RangeProofListBytes{})
	network.RegisterMessage(libunlynxshuffle.PublishedShufflingProofBytes{})
	network.RegisterMessage(libunlynxkeyswitch.PublishedKSListProofBytes{})
	network.RegisterMessage(libunlynxaggr.PublishedAggregationListProofBytes{})
	network.RegisterMessage(libdrynx.PublishedListObfuscationProofBytes{})

	log.SetDebugVisible(1)

	nbrProofs := 2

	local := onet.NewLocalTest(libunlynx.SuiTe)
	defer local.CloseAll()

	onet.GlobalProtocolRegister("ProofCollectionTest", NewProofCollectionTest)
	_, el, tree := local.GenTree(4, true)

	senderID := el.List[0].String()

	// generate a roster only with the verifying nodes
	el = onet.NewRoster(el.List[1:])

	// initialize parameters for test
	surveyID := uuid.NewV4().String()
	sharedBMChannel = make(chan map[string]int64, 100)
	sharedBMChannelToTerminate = make(chan struct{}, 100)

	keys := key.NewKeyPair(libunlynx.SuiTe)
	priv, pub := keys.Private, keys.Public

	idToPublic := make(map[string]kyber.Point)
	idToPublic[senderID] = pub

	// generate query
	ps := make([]*[]libdrynx.PublishSignatureBytes, len(el.List))
	for i := range el.List {
		temp := make([]libdrynx.PublishSignatureBytes, nbrProofs)
		for j := 0; j < 2; j++ {
			temp[j] = libdrynx.InitRangeProofSignature(16) // u is the first elem
		}
		ps[i] = &temp
	}
	// two range proofs
	ranges := make([]*[]int64, nbrProofs)
	for i := range ranges {
		ranges[i] = &[]int64{16, 16}
	}
	testSQ = generateTestSurveyQuery(surveyID, el, idToPublic, ps, ranges)

	// initialize each node's 'tools' (these have to be independent for each different VN node)
	nodeToolsMap = make(map[string]*nodeTools)
	for i, node := range el.List {
		request := concurrent.NewConcurrentMap()

		//Order of proof is Range, Aggr, Obf, Shuffle, KeySwitch
		sizeQuery := make([]int, 0)
		sizeQuery = append(sizeQuery, nbrProofs)
		sizeQuery = append(sizeQuery, nbrProofs)
		sizeQuery = append(sizeQuery, nbrProofs)
		sizeQuery = append(sizeQuery, nbrProofs)
		sizeQuery = append(sizeQuery, nbrProofs)

		request.Put(surveyID, &libdrynx.QueryInfo{Bitmap: make(map[string]int64), TotalNbrProofs: sizeQuery, Query: &testSQ, EndVerificationChannel: make(chan skipchain.SkipBlock, 100)})

		dbPath := "test" + strconv.FormatInt(int64(i), 10)
		db, err := bbolt.Open(dbPath, 0600, nil)
		if err != nil {
			log.Fatal("Open database failed:", err)
		}
		mutex := &sync.Mutex{}

		nodeToolsMap[node.String()] = &nodeTools{request: request, dbPath: dbPath, db: db, mutex: mutex}
	}

	// generate test proofs
	testProofs := libdrynx.CreateRandomGoodTestData(el, pub, ps, ranges, nbrProofs)

	// 5 is the number of different proofs
	totalNbrProofs := nbrProofs * 5
	wg := libunlynx.StartParallelize(totalNbrProofs)
	// send range proofs
	for i := range testProofs.ProofsRange {
		go func(index int) {
			defer (*wg).Done()

			rootInstance, err := local.CreateProtocol("ProofCollectionTest", tree)
			if err != nil {
				t.Fatal("Couldn't start protocol:", err)
			}
			protocol := rootInstance.(*ProofCollectionProtocol)

			protocol.Proof = libdrynx.ProofRequest{RangeProof: libdrynx.NewRangeProofRequest(testProofs.ProofsRange[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, libdrynx.ProofTrue, v, "There are some false range proofs")
			}
		}(i)
	}
	log.Lvl2("\n")
	log.Lvl2("#-------------------------------#")
	log.Lvl2("Finished sending RANGE proofs")
	log.Lvl2("#-------------------------------#\n")

	// send aggregation proofs
	for i := range testProofs.ProofsAggregation {
		go func(index int) {
			defer (*wg).Done()

			rootInstance, err := local.CreateProtocol("ProofCollectionTest", tree)
			if err != nil {
				t.Fatal("Couldn't start protocol:", err)
			}
			protocol := rootInstance.(*ProofCollectionProtocol)

			protocol.Proof = libdrynx.ProofRequest{AggregationProof: libdrynx.NewAggregationProofRequest(testProofs.ProofsAggregation[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, libdrynx.ProofTrue, v, "There are some false aggregation proofs")
			}

		}(i)
	}
	log.Lvl2("\n")
	log.Lvl2("#-------------------------------#")
	log.Lvl2("Finished sending AGGREGATION proofs")
	log.Lvl2("#-------------------------------#\n")

	// send aggregation proofs
	for i := range testProofs.ProofsObfuscation {
		go func(index int) {
			defer (*wg).Done()

			rootInstance, err := local.CreateProtocol("ProofCollectionTest", tree)
			if err != nil {
				t.Fatal("Couldn't start protocol:", err)
			}
			protocol := rootInstance.(*ProofCollectionProtocol)

			protocol.Proof = libdrynx.ProofRequest{ObfuscationProof: libdrynx.NewObfuscationProofRequest(testProofs.ProofsObfuscation[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, libdrynx.ProofTrue, v, "There are some false obfuscation proofs")
			}

		}(i)
	}
	log.Lvl2("\n")
	log.Lvl2("#-------------------------------#")
	log.Lvl2("Finished sending OBFUSCATION proofs")
	log.Lvl2("#-------------------------------#\n")

	// send shuffle proofs
	for i := range testProofs.ProofShuffle {
		go func(index int) {
			defer (*wg).Done()

			rootInstance, err := local.CreateProtocol("ProofCollectionTest", tree)
			if err != nil {
				t.Fatal("Couldn't start protocol:", err)
			}
			protocol := rootInstance.(*ProofCollectionProtocol)

			protocol.Proof = libdrynx.ProofRequest{ShuffleProof: libdrynx.NewShuffleProofRequest(testProofs.ProofShuffle[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, libdrynx.ProofTrue, v, "There are some false shuffle proofs")
			}
		}(i)
	}
	log.Lvl2("\n")
	log.Lvl2("#-------------------------------#")
	log.Lvl2("Finished sending SHUFFLE proofs")
	log.Lvl2("#-------------------------------#\n")

	// send key switch proofs
	for i := range testProofs.ProofsKeySwitch {
		go func(index int) {
			defer (*wg).Done()

			rootInstance, err := local.CreateProtocol("ProofCollectionTest", tree)
			if err != nil {
				t.Fatal("Couldn't start protocol:", err)
			}
			protocol := rootInstance.(*ProofCollectionProtocol)

			protocol.Proof = libdrynx.ProofRequest{KeySwitchProof: libdrynx.NewKeySwitchProofRequest(testProofs.ProofsKeySwitch[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, libdrynx.ProofTrue, v, "There are some false key switch proofs")
			}
		}(i)
	}

	// read all bitmaps
	aggregateBitmap := make(map[string]int64)
	for i := 0; i < len(el.List); i++ {
		res := <-sharedBMChannel

		for key, value := range res {
			aggregateBitmap[key] = value
		}
	}

	// terminate all protocols
	for i := 0; i < totalNbrProofs; i++ {
		sharedBMChannelToTerminate <- struct{}{}
	}

	libunlynx.EndParallelize(wg)

	log.Lvl2("\n")
	log.Lvl2("#-------------------------------#")
	log.Lvl2("Finished sending KEYSWITCH proofs")
	log.Lvl2("#-------------------------------#\n")

	for _, v := range nodeToolsMap {
		err := v.db.Close()
		if err != nil {
			log.Fatal("Close database failed:", err)
		}
		err = os.Remove(v.dbPath)
		if err != nil {
			log.Fatal("Delete database failed:", err)
		}
	}
}

func generateTestSurveyQuery(surveyID string, el *onet.Roster, idToPublic map[string]kyber.Point, ps []*[]libdrynx.PublishSignatureBytes, ranges []*[]int64) libdrynx.SurveyQuery {
	diffP := libdrynx.QueryDiffP{Scale: 1.0, Quanta: 1.0, NoiseListSize: 1, Limit: 1.0, LapMean: 1.0, LapScale: 1.0}

	iVSigs := libdrynx.QueryIVSigs{InputValidationSigs: ps, InputValidationSize1: len(el.List), InputValidationSize2: len(ranges)}
	query := libdrynx.Query{DiffP: diffP, Operation: libdrynx.Operation{NbrInput: 1, NbrOutput: 1}, Ranges: ranges, IVSigs: iVSigs, Proofs: 1}
	sq := libdrynx.SurveyQuery{RosterServers: *el, SurveyID: surveyID, Query: query, ClientPubKey: nil, ServerToDP: nil, IDtoPublic: idToPublic, Threshold: 1.0, AggregationProofThreshold: 1.0, RangeProofThreshold: 1.0, ObfuscationProofThreshold: 1.0, KeySwitchingProofThreshold: 1.0}

	return sq
}

// NewProofCollectionTest is a test specific protocol instance constructor that injects test data.
func NewProofCollectionTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := NewProofCollectionProtocol(tni)
	protocol := pi.(*ProofCollectionProtocol)

	if !tni.IsRoot() {
		protocol.SQ = testSQ
		protocol.SharedBMChannel = sharedBMChannel
		protocol.SharedBMChannelToTerminate = sharedBMChannelToTerminate

		for k, v := range nodeToolsMap {
			if k == tni.ServerIdentity().String() {
				protocol.Request = v.request
				protocol.DBPath = v.dbPath
				protocol.DB = v.db
				protocol.Mutex = v.mutex

			}
		}
	}
	return protocol, err
}
