package protocols

import (
	"testing"

	"sync"

	"os"

	"strconv"

	"github.com/coreos/bbolt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/satori/go.uuid.v1"
	"github.com/lca1/drynx/lib"
)

type nodeTools struct {
	request     *concurrent.ConcurrentMap
	dataOfBlock *concurrent.ConcurrentMap
	dbPath      string
	db          *bolt.DB
	mutex       *sync.Mutex
}

var nodeToolsMap map[string]*nodeTools
var testSQ lib.SurveyQuery
var sharedBMChannel chan map[string]int64
var sharedBMChannelToTerminate chan struct{}

//TestProofCollectionProtocol tests collective aggregation protocol
func TestProofCollectionProtocol(t *testing.T) {
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

	priv, pub := libunlynx.GenKey()
	idToPublic := make(map[string]kyber.Point)
	idToPublic[senderID] = pub

	// generate query
	ps := make([]*[]lib.PublishSignatureBytes, len(el.List))
	for i := range el.List {
		temp := make([]lib.PublishSignatureBytes, nbrProofs)
		for j := 0; j < 2; j++ {
			temp[j] = lib.InitRangeProofSignature(16) // u is the first elem
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

		request.Put(surveyID, &lib.QueryInfo{Bitmap: make(map[string]int64), TotalNbrProofs: sizeQuery, Query: &testSQ, EndVerificationChannel: make(chan skipchain.SkipBlock, 100)})

		dbPath := "test" + strconv.FormatInt(int64(i), 10)
		db, err := bolt.Open(dbPath, 0600, nil)
		if err != nil {
			log.Fatal("Open database failed:", err)
		}
		mutex := &sync.Mutex{}

		nodeToolsMap[node.String()] = &nodeTools{request: request, dbPath: dbPath, db: db, mutex: mutex}
	}

	// generate test proofs
	testProofs := lib.CreateRandomGoodTestData(el, pub, ps, ranges, nbrProofs)

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

			protocol.Proof = lib.ProofRequest{RangeProof: lib.NewRangeProofRequest(testProofs.ProofsRange[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, lib.PROOF_TRUE, v, "There are some false range proofs")
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

			protocol.Proof = lib.ProofRequest{AggregationProof: lib.NewAggregationProofRequest(testProofs.ProofsAggregation[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, lib.PROOF_TRUE, v, "There are some false aggregation proofs")
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

			protocol.Proof = lib.ProofRequest{ObfuscationProof: lib.NewObfuscationProofRequest(testProofs.ProofsObfuscation[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, lib.PROOF_TRUE, v, "There are some false obfuscation proofs")
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

			protocol.Proof = lib.ProofRequest{ShuffleProof: lib.NewShuffleProofRequest(testProofs.ProofShuffle[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, lib.PROOF_TRUE, v, "There are some false shuffle proofs")
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

			protocol.Proof = lib.ProofRequest{KeySwitchProof: lib.NewKeySwitchProofRequest(testProofs.ProofsKeySwitch[index], surveyID, senderID, strconv.FormatInt(int64(index), 10), el, priv, nil)}

			//run protocol
			go protocol.Start()
			res := <-protocol.FeedbackChannel

			//check if all proofs are true
			for _, v := range res.Bitmap {
				assert.Equal(t, lib.PROOF_TRUE, v, "There are some false key switch proofs")
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

func generateTestSurveyQuery(surveyID string, el *onet.Roster, idToPublic map[string]kyber.Point, ps []*[]lib.PublishSignatureBytes, ranges []*[]int64) lib.SurveyQuery {
	diffP := lib.QueryDiffP{Scale: 1.0, Quanta: 1.0, NoiseListSize: 1, Limit: 1.0, LapMean: 1.0, LapScale: 1.0}

	iVSigs := lib.QueryIVSigs{InputValidationSigs: ps, InputValidationSize1: len(el.List), InputValidationSize2: len(ranges)}
	query := lib.Query{DiffP: diffP, Operation: lib.Operation{NbrInput: 1, NbrOutput: 1}, Ranges: ranges, IVSigs: iVSigs, Proofs: 1}
	sq := lib.SurveyQuery{RosterServers: *el, SurveyID: surveyID, Query: query, ClientPubKey: nil, ServerToDP: nil, IDtoPublic: idToPublic, Threshold: 1.0, RangeProofThreshold: 1.0, ObfuscationProofThreshold: 1.0, KeySwitchingProofThreshold: 1.0}

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
