package protocols_test

import (
	"go.dedis.ch/kyber/v3/util/key"
	"testing"

	"time"

	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/provider/loaders"
	"github.com/ldsec/drynx/protocols"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func createTestQuery(aggregate kyber.Point, operationName string, proofs int, nbrRows int64, minGenerateData, maxGenerateData, dimensions int, cuttingFactor int) (protocols.SurveyToDP, error) {
	var queryStatement protocols.SurveyToDP
	var query libdrynx.Query

	queryStatement.SurveyID = "query_test"
	queryStatement.Aggregate = aggregate

	query.Operation = libdrynx.ChooseOperation(operationName, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
	query.Proofs = proofs

	// define the number of groups for groupBy (1 per default)
	dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}
	query.DPDataGen = dpData

	queryStatement.Query = query

	return queryStatement, nil
}

var query protocols.SurveyToDP

// TestDataCollectionOperationsProtocol tests data collection protocol
func TestDataCollectionOperationsProtocol(t *testing.T) {
	log.SetDebugVisible(2)

	local := onet.NewLocalTest(libunlynx.SuiTe)
	defer local.CloseAll()

	if _, err := onet.GlobalProtocolRegister("DataCollectionTest", NewDataCollectionTest); err != nil {
		log.Fatal("Failed to register the <DataCollectionTest> protocol:", err)
	}
	_, _, tree := local.GenTree(10, true)

	operationList := []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg"}
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	for _, op := range operationList {
		// create query
		var err error
		query, err = createTestQuery(pubKey, op, 0, 10, 1, 2, 5, 0)
		assert.Nil(t, err, "Error when generating test query")

		rootInstance, err := local.CreateProtocol("DataCollectionTest", tree)
		if err != nil {
			t.Fatal("Couldn't start protocol:", err)
		}
		protocol := rootInstance.(*protocols.DataCollectionProtocol)

		//run protocol
		go func() {
			if err := protocol.Start(); err != nil {
				log.Fatal(err)
			}
		}()

		timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond
		feedback := protocol.FeedbackChannel

		select {
		case result := <-feedback:
			// decrypt results
			log.Lvl1("Final result [", op, "]:")
			for keyV, value := range result {
				listResults := libunlynx.DecryptIntVector(secKey, &value)
				log.Lvl1(keyV, ":", listResults)
			}

			continue
		case <-time.After(timeout):
			t.Fatal("Didn't finish in time")
		}
	}
}

// NewDataCollectionTest is a test specific protocol instance constructor that injects test data.
func NewDataCollectionTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	loader, err := loaders.NewRandom()
	if err != nil {
		return nil, err
	}

	dcp := protocols.NewDataCollectionProtocol(loader)
	dcp.Survey = query
	dcp.ProtocolRegister(tni)
	return &dcp, nil
}
