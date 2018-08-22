package protocols_test

import (
	"testing"

	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/common"
	"github.com/lca1/unlynx/services/lemal"
	"github.com/stretchr/testify/assert"
)

func ChooseOperation(operationName string, queryMin, queryMax, d int, cuttingFactor int) common.Operation {
	operation := common.Operation{}

	operation.NameOp = operationName
	operation.NbrInput = 0
	operation.NbrOutput = 0
	operation.QueryMax = int64(queryMax)
	operation.QueryMin = int64(queryMin)

	switch operationName {
	case "sum":
		operation.NbrInput = 1
		operation.NbrOutput = 1
		break
	case "mean":
		operation.NbrInput = 1
		operation.NbrOutput = 2
		break
	case "variance":
		operation.NbrInput = 1
		operation.NbrOutput = 3
		break
	case "cosim":
		operation.NbrInput = 2
		operation.NbrOutput = 5
		break
	case "frequencyCount", "min", "max", "union", "inter":
		//NbrOutput should be equal to (QueryMax - QueryMin + 1)
		operation.NbrInput = 1
		operation.NbrOutput = queryMax - queryMin + 1
		break
	case "bool_OR", "bool_AND":
		operation.NbrInput = 1
		operation.NbrOutput = 1
		break
	case "lin_reg":
		//NbrInput should be equal to d + 1, in the case of linear regression
		operation.NbrInput = d + 1
		operation.NbrOutput = (d*d + 5*d + 4) / 2
		break
	default:
		log.Fatal("Operation: <", operation, "> does not exist")
	}

	if cuttingFactor != 0 {
		operation.NbrOutput = operation.NbrOutput*cuttingFactor
	}

	return operation
}

func createTestQuery(aggregate kyber.Point, operationName string, proofs int, nbrRows int64, minGenerateData, maxGenerateData, dimensions int, cuttingFactor int) (lemal.SurveyToDP, error) {
	var queryStatement lemal.SurveyToDP
	var query common.Query

	queryStatement.SurveyID = "query_test"
	queryStatement.Aggregate = aggregate

	query.Operation = ChooseOperation(operationName, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
	query.Proofs = proofs

	// define the number of groups for groupBy (1 per default)
	dpData := common.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}
	query.DPDataGen = dpData

	queryStatement.Query = query

	/*
			// SurveyToDP is used to trigger the upload of data by a data provider
		type SurveyToDP struct {
			SurveyID  string
			Aggregate kyber.Point // The joint key to encrypt the data
			Sigs      []*[]libunlynx.PublishSignatureBytes
			SigsSize1 int
			SigsSize2 int
			// query statement
			Query common.Query
		}

			// Query is used to transport query information through servers, to DPs
		type Query struct {
			// query statement
			Operation Operation
			Ranges    []*[]int64
			Proofs    int
			DiffP     QueryDiffP

			// define how the DPs generate dummy data
			DPDataGen QueryDPDataGen

			// identity skipchain simulation
			IVSigs    QueryIVSigs
			RosterVNs *onet.Roster

			// if real DB at data providers
			SQL QuerySQL
		}

	*/

	return queryStatement, nil
}

var query lemal.SurveyToDP

//TestCollectiveAggregation tests collective aggregation protocol
func TestDataCollectionOperationsProtocol(t *testing.T) {
	libunlynx.TIME = false
	log.SetDebugVisible(2)

	local := onet.NewLocalTest(libunlynx.SuiTe)
	defer local.CloseAll()

	onet.GlobalProtocolRegister("DataCollectionTest", NewDataCollectionTest)
	_, _, tree := local.GenTree(10, true)

	operationList := []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg"}
	secKey, pubKey := libunlynx.GenKey()

	for _, op := range operationList {
		// create query
		var err error
		query, err = createTestQuery(pubKey, op, 0, 10, 1, 2, 5, 0)
		assert.Nil(t, err, "Error when generating test query")

		rootInstance, err := local.CreateProtocol("DataCollectionTest", tree)
		if err != nil {
			t.Fatal("Couldn't start protocol:", err)
		}
		protocol := rootInstance.(*lemal.DataCollectionProtocol)

		//run protocol
		go protocol.Start()

		timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond
		feedback := protocol.FeedbackChannel

		select {
		case result := <-feedback:
			// decrypt results
			log.Lvl1("Final result [", op, "]:")
			for key, value := range result {
				listResults := libunlynx.DecryptIntVector(secKey, &value)
				log.Lvl1(key, ":", listResults)

				/*switch op {
				case "sum", "min", "max":
					log.Lvl2("NO", listResults[0])
					log.Lvl2(assert.Equal(t, int64(90), listResults[0], "Wrong result")) // sum
					break
				case "mean":
					assert.Equal(t, int64(90), listResults[0]) // sum
					assert.Equal(t, int64(90), listResults[1]) // count
					break
				case "variance":
					assert.Equal(t, int64(90), listResults[0]) // sum
					assert.Equal(t, int64(90), listResults[1]) // count
					assert.Equal(t, int64(90), listResults[2]) // sum of squares
					break
				case "cosim":
					break
				case "frequencyCount":
					assert.Equal(t, int64(90), listResults[0]) // sum
					break
				case "union":
					break
				case "inter":
					break
				case "bool_OR":
					break
				case "bool_AND":
					break
				case "lin_reg":
					break
				default:
					log.Fatal("Operation: <", op, "> does not exist")
				}*/
			}

			//assert.Equal(t, exprectedResult(op), result)
			continue
		case <-time.After(timeout):
			t.Fatal("Didn't finish in time")
		}
	}
}

// NewDataCollectionTest is a test specific protocol instance constructor that injects test data.
func NewDataCollectionTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := lemal.NewDataCollectionProtocol(tni)
	protocol := pi.(*lemal.DataCollectionProtocol)

	protocol.Survey = query
	return protocol, err
}
