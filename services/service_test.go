package services_test

import (
	"fmt"
	"go.dedis.ch/cothority/v3"

	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"gopkg.in/satori/go.uuid.v1"

	"math"
	"os"
	"strconv"
	"sync"
	"testing"

	"github.com/lca1/drynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/cothority/v3/skipchain"

	"github.com/lca1/drynx/services"
)

func generateNodes(local *onet.LocalTest, nbrServers int, nbrDPs int, nbrVNs int) (*onet.Roster, *onet.Roster, *onet.Roster) {
	_, elTotal, _ := local.GenTree(nbrServers+nbrDPs+nbrVNs, true)

	// create servers and data providers
	elServers := elTotal.List[:nbrServers]
	//data providers
	elDPs := elTotal.List[nbrServers : nbrServers+nbrDPs]
	//VNs
	elVNs := elTotal.List[nbrServers+nbrDPs : nbrServers+nbrDPs+nbrVNs]

	rosterServers := onet.NewRoster(elServers)
	rosterDPs := onet.NewRoster(elDPs)
	rosterVNs := onet.NewRoster(elVNs)

	return rosterServers, rosterDPs, rosterVNs
}

// how to repartition the DPs: each server as a list of data providers
func repartitionDPs(elServers *onet.Roster, elDPs *onet.Roster, dpRepartition []int64) map[string]*[]network.ServerIdentity {
	if len(dpRepartition) > len(elServers.List) {
		log.Fatal("Cannot assign the DPs to", len(dpRepartition), "servers (", len(elServers.List), ")")
	}

	dpToServers := make(map[string]*[]network.ServerIdentity, 0)
	count := 0
	for i, v := range elServers.List {
		index := v.String()
		value := make([]network.ServerIdentity, dpRepartition[i])
		dpToServers[index] = &value
		for j := range *dpToServers[index] {
			val := elDPs.List[count]
			count = count + 1
			(*dpToServers[index])[j] = *val
		}
	}

	return dpToServers
}

//______________________________________________________________________________________________________________________
/// Test service Drynx for all operations
func TestServiceDrynx(t *testing.T) {
	t.Skip("not this one")
	log.SetDebugVisible(1)

	//------SET PARAMS--------

	proofs := 1 // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := true
	obfuscation := false

	diffPri := true
	diffPriOpti := true
	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 5
	nbrVNs := 3
	repartition := []int64{2, 1, 2} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := 0

	operationList := []string{"frequencyCount"} //, "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg", "union", "inter"}
	//operationList := []string{"sum", "mean", "variance", "cosim", "frequencyCount", "lin_reg"}
	//operationList := []string{"bool_AND", "bool_OR", "min", "max", "union", "inter"}
	//operationList := []string{"variance"}
	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//------------------------

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}

	local := onet.NewLocalTest(cothority.Suite)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {

		// data providers data generation
		minGenerateData := 3
		maxGenerateData := 4
		dimensions := 5
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)

		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)

		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {
			ranges = nil
		}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1, Optimized: diffPriOpti}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0, Optimized: diffPriOpti}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
		//var modulo int
		//if cuttingFactor != 0 {
		//	modulo = operation.NbrOutput / cuttingFactor
		//}
		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// QUERY RECAP
		log.Lvl1("\n")
		log.Lvl1("#----- QUERY -----#")
		log.Lvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
			}
		}

		// query generation

		surveyID := "query-" + op

		sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

			wg = libunlynx.StartParallelize(1)
			go func(elVNs *onet.Roster) {
				defer wg.Done()

				err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
				if err != nil {
					log.Fatal("Error sending query to VNs:", err)
				}
			}(elVNs)
			libunlynx.EndParallelize(wg)

			wgProofs[i] = libunlynx.StartParallelize(1)
			go func(index int, si *network.ServerIdentity) {
				defer wgProofs[index].Done()

				sb, err := clientSkip.SendEndVerification(si, surveyID)
				if err != nil {
					log.Fatal("Error starting the 'waiting' threads:", err)
				}
				listBlocks[index] = sb
			}(i, elVNs.List[0])
		}

		// send query and receive results
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}

	}

	if proofs != 0 {
		clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip")
		for _, wg := range wgProofs {
			libunlynx.EndParallelize(wg)
		}

		// check genesis block
		if len(listBlocks) > 2 {
			sb, err := clientSkip.SendGetGenesis(elVNs.List[0])
			if err != nil {
				t.Fatal("Something wrong when fetching genesis block")
			}
			assert.Equal(t, sb.Data, listBlocks[0].Data)

			sb, err = clientSkip.SendGetLatestBlock(elVNs, listBlocks[0])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			sbRepeat, err := clientSkip.SendGetLatestBlock(elVNs, listBlocks[2])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			assert.Equal(t, sb.Data, sbRepeat.Data)
		}

		queryMean := false
		for i, op := range operationList {
			if op == "mean" && i == 1 {
				queryMean = true
			}
		}

		// only check the blocks when testing all the operation (mean operation must be executed in 2nd place
		if queryMean {
			// check getting one random block
			sb, err := clientSkip.SendGetBlock(elVNs, "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' block:", err)
			}
			assert.Equal(t, sb.Data, listBlocks[1].Data)

			res, err := clientSkip.SendGetProofs(elVNs.List[0], "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' form the DB", err)
			}

			// just check if map is not empty
			assert.NotEmpty(t, res)
		}

		// close DB
		clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
	}
}

func TestServiceDrynxLogisticRegressionForSPECTF(t *testing.T) {
	//t.Skip("not this one")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)

	//------SET PARAMS--------

	proofs := 0 // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false

	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 3
	nbrVNs := 3
	repartition := []int64{1, 1, 1} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := 0

	// ---- simulation parameters -----
	numberTrials := 1
	// 0: train together, test together
	// 1: train together, test separate
	// 2: train separate, test separate
	standardisationMode := 0
	scale := 1e0

	// ---- SPECTF dataset parameters ----
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.012, MaxIterations: 450,
		InitialWeights: []float64{
			0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
			0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
			-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
			0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
			-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}}

	//load the data
	filePathTraining := "../data/SPECTF_heart_dataset_training.txt"
	filePathTesting := "../data/SPECTF_heart_dataset_testing.txt"

	XTrain, _ := encoding.LoadData("SPECTF", filePathTraining)
	XTest, yTest := encoding.LoadData("SPECTF", filePathTesting)

	var means = make([]float64, 0)
	var standardDeviations = make([]float64, 0)
	if standardisationMode == 0 || standardisationMode == 1 {
		means = encoding.ComputeMeans(XTrain)
		standardDeviations = encoding.ComputeStandardDeviations(XTrain)
	} else {
		means = nil
		standardDeviations = nil
	}

	lrParameters.DatasetName = "SPECTF"
	lrParameters.FilePath = filePathTraining
	lrParameters.NbrRecords = int64(len(XTrain))
	lrParameters.NbrFeatures = int64(len(XTrain[0]))
	lrParameters.Means = means
	lrParameters.StandardDeviations = standardDeviations

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	operationList := []string{"logistic regression"}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//------------------------

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}

	local := onet.NewLocalTest(cothority.Suite)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {

		// data providers data generation
		minGenerateData := 3
		maxGenerateData := 4
		dimensions := 5
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
		operation.LRParameters = lrParameters
		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)

		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {
			ranges = nil
		}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
		//var modulo int
		//if cuttingFactor != 0 {
		//	modulo = operation.NbrOutput / cuttingFactor
		//}
		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// QUERY RECAP
		log.Lvl1("\n")
		log.Lvl1("#----- QUERY -----#")
		log.Lvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
			}
		}

		// query generation

		surveyID := "query-" + op

		sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

			wg = libunlynx.StartParallelize(1)
			go func(elVNs *onet.Roster) {
				defer wg.Done()

				err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
				if err != nil {
					log.Fatal("Error sending query to VNs:", err)
				}
			}(elVNs)
			libunlynx.EndParallelize(wg)

			wgProofs[i] = libunlynx.StartParallelize(1)
			go func(index int, si *network.ServerIdentity) {
				defer wgProofs[index].Done()

				sb, err := clientSkip.SendEndVerification(si, surveyID)
				if err != nil {
					log.Fatal("Error starting the 'waiting' threads:", err)
				}
				listBlocks[index] = sb
			}(i, elVNs.List[0])
		}

		// send query and receive results
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}
		if len(*aggr) != 0 {
			weights := (*aggr)[0]
			if standardisationMode == 1 || standardisationMode == 2 {
				means = nil
				standardDeviations = nil
			}
			accuracy, precision, recall, fscore, auc := performanceEvaluation(weights, XTest, yTest, means, standardDeviations)

			meanAccuracy += accuracy
			meanPrecision += precision
			meanRecall += recall
			meanFscore += fscore
			meanAUC += auc
		}
	}

	meanAccuracy /= float64(numberTrials)
	meanPrecision /= float64(numberTrials)
	meanRecall /= float64(numberTrials)
	meanFscore /= float64(numberTrials)
	meanAUC /= float64(numberTrials)

	fmt.Println("Final evaluation over", numberTrials, "trials")
	fmt.Println("accuracy: ", meanAccuracy)
	fmt.Println("precision:", meanPrecision)
	fmt.Println("recall:   ", meanRecall)
	fmt.Println("F-score:  ", meanFscore)
	fmt.Println("AUC:      ", meanAUC)
	fmt.Println()
	log.Lvl1("ICI")
	//encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	if proofs != 0 {
		clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip")
		for _, wg := range wgProofs {
			libunlynx.EndParallelize(wg)
		}

		// check genesis block
		if len(listBlocks) > 2 {
			sb, err := clientSkip.SendGetGenesis(elVNs.List[0])
			if err != nil {
				t.Fatal("Something wrong when fetching genesis block")
			}
			assert.Equal(t, sb.Data, listBlocks[0].Data)

			sb, err = clientSkip.SendGetLatestBlock(elVNs, listBlocks[0])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			sbRepeat, err := clientSkip.SendGetLatestBlock(elVNs, listBlocks[2])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			assert.Equal(t, sb.Data, sbRepeat.Data)
		}

		queryMean := false
		for i, op := range operationList {
			if op == "mean" && i == 1 {
				queryMean = true
			}
		}

		// only check the blocks when testing all the operation (mean operation must be executed in 2nd place
		if queryMean {
			// check getting one random block
			sb, err := clientSkip.SendGetBlock(elVNs, "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' block:", err)
			}
			assert.Equal(t, sb.Data, listBlocks[1].Data)

			res, err := clientSkip.SendGetProofs(elVNs.List[0], "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' form the DB", err)
			}

			// just check if map is not empty
			assert.NotEmpty(t, res)
		}

		// close DB
		clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
	}
}

func TestServiceDrynxLogisticRegression(t *testing.T) {
	t.Skip("Only use to locally train a specific dataset")
	os.Remove("pre_compute_multiplications.gob")

	// these nodes act as both servers and data providers
	local := onet.NewLocalTest(cothority.Suite)
	local1 := onet.NewLocalTest(cothority.Suite)
	local2 := onet.NewLocalTest(cothority.Suite)

	// create servers and data providers
	_, el, _ := local.GenTree(10, true)
	//data providers
	_, el1, _ := local1.GenTree(10, true)
	//VNS
	_, elVNs, _ := local2.GenTree(3, true)
	//repartition
	dpRepartition := []int64{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	//dpRepartition := []int64{1}
	dpToServers := make(map[string]*[]network.ServerIdentity, 0)
	count := 0
	for i, v := range el.List {
		index := v.String()
		value := make([]network.ServerIdentity, dpRepartition[i])
		dpToServers[index] = &value
		for j := range *dpToServers[index] {
			val := el1.List[count]
			count = count + 1
			(*dpToServers[index])[j] = *val
		}
	}

	proofs := 0 // 0 is not proof, 1 is proofs, 2 is optimized proofs

	defer local.CloseAll()

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(el.List[0], strconv.Itoa(0))

	// ---- simulation parameters -----
	numberTrials := 10
	initSeed := int64(5432109876)
	// 0: train together, test together
	// 1: train together, test separate
	// 2: train separate, test separate
	standardisationMode := 2
	scale := 1e0

	// choose if differential privacy or not, no diffP by default
	//diffP := common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	diffP := libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
	// to activate

	// ---- PCS dataset parameters ----
	/*
		dataset := "PCS"
		ratio := 0.8
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
			InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0}}
		//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	*/
	// ---- Pima dataset parameters ----
	//*
	dataset := "Pima"
	ratio := 0.75
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.1, MaxIterations: 200, InitialWeights: []float64{0.334781, -0.633628, 0.225721, -0.648192, 0.406207,
			0.044424, -0.426648, 0.877499, -0.426819}}
	diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 30.0, NoiseListSize: 90, Quanta: 0.0, Scale: scale, Limit: 60}
	//*/

	// ---- SPECTF dataset parameters ----
	/*
		dataset := "SPECTF"
		ratio := 0.3
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.012, MaxIterations: 450, InitialWeights: []float64{
					0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
					0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
					-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
					0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
					-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}}
		//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:15.0, NoiseListSize: 2070, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// ---- LBW dataset parameters ----
	/*
		dataset := "LBW"
		ratio := 0.8
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
			InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
		//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 110, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// create the filenames
	filepath := "../data/" + dataset + "_dataset.txt"
	filePathTraining := "../data/" + dataset + "_dataset_training.txt"
	filePathTesting := "../data/" + dataset + "_dataset_testing.txt"

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	log.Lvl1("Simulating homomorphism-aware logistic regression for the " + dataset + " dataset")
	fmt.Println(filepath)

	// load the dataset
	X, y := encoding.LoadData(dataset, filepath)

	for i := 0; i < numberTrials; i++ {
		log.Lvl1("Evaluating prediction on dataset for trial:", i)

		// split into training and testing set
		seed := initSeed + int64(i)
		XTrain, yTrain, XTest, yTest := encoding.PartitionDataset(X, y, ratio, true, seed)

		// write to file
		trainingSet := encoding.InsertColumn(XTrain, encoding.Int64ToFloat641DArray(yTrain), 0)
		testingSet := encoding.InsertColumn(XTest, encoding.Int64ToFloat641DArray(yTest), 0)

		fileTraining, err := os.Create(filePathTraining)
		fileTesting, err := os.Create(filePathTesting)

		for i := 0; i < len(trainingSet); i++ {
			for j := 0; j < len(trainingSet[i])-1; j++ {
				_, err = fileTraining.WriteString(fmt.Sprint(trainingSet[i][j]) + ",")
			}
			_, err = fileTraining.WriteString(fmt.Sprintln(trainingSet[i][len(trainingSet[i])-1]))
		}

		for i := 0; i < len(testingSet); i++ {
			for j := 0; j < len(testingSet[i])-1; j++ {
				_, err = fileTesting.WriteString(fmt.Sprint(testingSet[i][j]) + ",")
			}
			_, err = fileTesting.WriteString(fmt.Sprintln(testingSet[i][len(testingSet[i])-1]))
		}

		var means = make([]float64, 0)
		var standardDeviations = make([]float64, 0)
		if standardisationMode == 0 || standardisationMode == 1 {
			means = encoding.ComputeMeans(XTrain)
			standardDeviations = encoding.ComputeStandardDeviations(XTrain)
		} else {
			means = nil
			standardDeviations = nil
		}

		lrParameters.FilePath = filePathTraining
		lrParameters.NbrRecords = int64(len(trainingSet))
		lrParameters.NbrFeatures = int64(len(XTrain[0]))
		lrParameters.Means = means
		lrParameters.StandardDeviations = standardDeviations

		operation := libdrynx.Operation{NameOp: "logistic regression", LRParameters: lrParameters}

		// data providers data generation
		// define the number of groups for groupBy (1 per default)
		minGenerateData := int64(0)
		maxGenerateData := int64(2)
		if operation.QueryMax != 0 {
			minGenerateData = operation.QueryMin
			maxGenerateData = operation.QueryMax
		}
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{}, GenerateRows: 100, GenerateDataMin: minGenerateData, GenerateDataMax: maxGenerateData}

		// define the ranges for the input validation (1 range per data provider output)
		u := int64(2)
		l := int64(6)

		ranges := make([]*[]int64, operation.NbrOutput)
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(el.List))
		for i := range ranges {
			ranges[i] = &[]int64{u, l}
		}
		// if no input validation
		//ranges = nil

		// signatures for Input Validation
		if !(ranges == nil) {
			for i := range el.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// query parameters recap
		log.Lvl1("Service Drynx Test with suite: ", libunlynx.SuiTe.String(), " and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP0, ..., DP", len(el1.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")

		idToPublic := make(map[string]kyber.Point)
		for _, v := range el.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range el1.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elVNs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
		// query sending + results receiving
		cuttingFactor := 0
		sq := client.GenerateSurveyQuery(el, elVNs, dpToServers, idToPublic, uuid.NewV4().String(), operation, ranges, ps, proofs, false, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}

		if len(*aggr) != 0 {
			weights := (*aggr)[0]
			if standardisationMode == 1 || standardisationMode == 2 {
				means = nil
				standardDeviations = nil
			}
			accuracy, precision, recall, fscore, auc := performanceEvaluation(weights, XTest, yTest, means, standardDeviations)

			meanAccuracy += accuracy
			meanPrecision += precision
			meanRecall += recall
			meanFscore += fscore
			meanAUC += auc
		}

		fileTraining.Close()
		fileTesting.Close()
	}

	meanAccuracy /= float64(numberTrials)
	meanPrecision /= float64(numberTrials)
	meanRecall /= float64(numberTrials)
	meanFscore /= float64(numberTrials)
	meanAUC /= float64(numberTrials)

	fmt.Println("Final evaluation over", numberTrials, "trials")
	fmt.Println("accuracy: ", meanAccuracy)
	fmt.Println("precision:", meanPrecision)
	fmt.Println("recall:   ", meanRecall)
	fmt.Println("F-score:  ", meanFscore)
	fmt.Println("AUC:      ", meanAUC)
	fmt.Println()

	encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)
}

func performanceEvaluation(weights []float64, XTest [][]float64, yTest []int64, means []float64,
	standardDeviations []float64) (float64,
	float64, float64, float64, float64) {
	fmt.Println("weights:", weights)

	if means != nil && standardDeviations != nil &&
		len(means) > 0 && len(standardDeviations) > 0 {
		// using global means and standard deviations, if given
		log.Lvl1("Standardising the testing set with global means and standard deviations...")
		XTest = encoding.StandardiseWith(XTest, means, standardDeviations)
	} else {
		// using local means and standard deviations, if not given
		log.Lvl1("Standardising the testing set with local means and standard deviations...")
		XTest = encoding.Standardise(XTest)
	}

	predictions := make([]int64, len(XTest))
	predictionsFloat := make([]float64, len(XTest))
	for i := range XTest {
		predictionsFloat[i] = encoding.PredictInClear(XTest[i], weights)
		predictions[i] = int64(math.Round(predictionsFloat[i]))
		fmt.Printf("%12.8e %1d %2d\n", predictionsFloat[i], predictions[i], yTest[i])
	}

	accuracy := encoding.Accuracy(predictions, yTest)
	precision := encoding.Precision(predictions, yTest)
	recall := encoding.Recall(predictions, yTest)
	fscore := encoding.Fscore(predictions, yTest)
	auc := encoding.AreaUnderCurve(predictionsFloat, yTest)

	fmt.Println("accuracy: ", accuracy)
	fmt.Println("precision:", precision)
	fmt.Println("recall:   ", recall)
	fmt.Println("F-score:  ", fscore)
	fmt.Println("AUC:      ", auc)
	fmt.Println()

	//encoding.PlotROC(predictionsFloat, yTest)

	// compute the TPR (True Positive Rate) and FPR (False Positive Rate)
	//tpr, fpr := encoding.ComputeTPRFPR(predictionsFloat, yTest)
	// save to file (for plotting the ROC)
	//encoding.SaveToFile(tpr, "../data/tpr.txt")
	//encoding.SaveToFile(fpr, "../data/fpr.txt")

	return accuracy, precision, recall, fscore, auc
}

func TestServiceDrynxLogisticRegressionV2(t *testing.T) {
	//t.Skip("NOP")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)

	//------SET PARAMS--------

	proofs := 0 // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false

	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 3
	nbrVNs := 3
	repartition := []int64{1, 1, 1} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := 0

	// ---- simulation parameters -----
	numberTrials := 1
	// 0: train together, test together
	// 1: train together, test separate
	// 2: train separate, test separate
	standardisationMode := 0
	scale := 1e0

	// ---- PCS dataset parameters ----
	/*
		dataset := "PCS"
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
			InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0}}
		lrParameters.DatasetName = "PCS"
		//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	*/
	// ---- Pima dataset parameters ----
	//*
	dataset := "Pima"
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.1, MaxIterations: 200, InitialWeights: []float64{0.334781, -0.633628, 0.225721, -0.648192, 0.406207,
			0.044424, -0.426648, 0.877499, -0.426819}}
	lrParameters.DatasetName = "Pima"
	//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	//*/

	// ---- SPECTF dataset parameters ----
	/*
		dataset := "SPECTF_heart"
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.012, MaxIterations: 450, InitialWeights: []float64{
					0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
					0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
					-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
					0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
					-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}}
		lrParameters.DatasetName = "SPECTF"
		//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:15.0, NoiseListSize: 2070, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// ---- LBW dataset parameters ----
	/*
		dataset := "LBW"
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
			InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
		//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 110, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// ---- SPECTF dataset parameters ----
	/*
		dataset := "SPECTF_heart"
		lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.012, MaxIterations: 450,
			InitialWeights: []float64{
				0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
				0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
				-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
				0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
				-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}}
	*/

	//load the data
	filePathTraining := "../data/" + dataset + "_dataset_training.txt"
	filePathTesting := "../data/" + dataset + "_dataset_testing.txt"

	XTrain, _ := encoding.LoadData(dataset, filePathTraining)
	XTest, yTest := encoding.LoadData(dataset, filePathTesting)

	var means = make([]float64, 0)
	var standardDeviations = make([]float64, 0)
	if standardisationMode == 0 || standardisationMode == 1 {
		means = encoding.ComputeMeans(XTrain)
		standardDeviations = encoding.ComputeStandardDeviations(XTrain)
	} else {
		means = nil
		standardDeviations = nil
	}

	lrParameters.FilePath = filePathTraining
	lrParameters.NbrRecords = int64(len(XTrain))
	lrParameters.NbrFeatures = int64(len(XTrain[0]))
	lrParameters.Means = means
	lrParameters.StandardDeviations = standardDeviations

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	operationList := []string{"logistic regression"}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//------------------------

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}

	local := onet.NewLocalTest(cothority.Suite)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {

		// data providers data generation
		minGenerateData := 3
		maxGenerateData := 4
		dimensions := 5
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
		operation.LRParameters = lrParameters
		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)

		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {
			ranges = nil
		}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
		//var modulo int
		//if cuttingFactor != 0 {
		//	modulo = operation.NbrOutput / cuttingFactor
		//}
		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// QUERY RECAP
		log.Lvl1("\n")
		log.Lvl1("#----- QUERY -----#")
		log.Lvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
			}
		}

		// query generation

		surveyID := "query-" + op

		sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

			wg = libunlynx.StartParallelize(1)
			go func(elVNs *onet.Roster) {
				defer wg.Done()

				err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
				if err != nil {
					log.Fatal("Error sending query to VNs:", err)
				}
			}(elVNs)
			libunlynx.EndParallelize(wg)

			wgProofs[i] = libunlynx.StartParallelize(1)
			go func(index int, si *network.ServerIdentity) {
				defer wgProofs[index].Done()

				sb, err := clientSkip.SendEndVerification(si, surveyID)
				if err != nil {
					log.Fatal("Error starting the 'waiting' threads:", err)
				}
				listBlocks[index] = sb
			}(i, elVNs.List[0])
		}

		// send query and receive results
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}
		if len(*aggr) != 0 {
			weights := (*aggr)[0]
			if standardisationMode == 1 || standardisationMode == 2 {
				means = nil
				standardDeviations = nil
			}
			accuracy, precision, recall, fscore, auc := performanceEvaluation(weights, XTest, yTest, means, standardDeviations)

			meanAccuracy += accuracy
			meanPrecision += precision
			meanRecall += recall
			meanFscore += fscore
			meanAUC += auc
		}
	}

	meanAccuracy /= float64(numberTrials)
	meanPrecision /= float64(numberTrials)
	meanRecall /= float64(numberTrials)
	meanFscore /= float64(numberTrials)
	meanAUC /= float64(numberTrials)

	fmt.Println("Final evaluation over", numberTrials, "trials")
	fmt.Println("accuracy: ", meanAccuracy)
	fmt.Println("precision:", meanPrecision)
	fmt.Println("recall:   ", meanRecall)
	fmt.Println("F-score:  ", meanFscore)
	fmt.Println("AUC:      ", meanAUC)
	fmt.Println()
	log.Lvl1("ICI")
	//encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	if proofs != 0 {
		clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip")
		for _, wg := range wgProofs {
			libunlynx.EndParallelize(wg)
		}

		// check genesis block
		if len(listBlocks) > 2 {
			sb, err := clientSkip.SendGetGenesis(elVNs.List[0])
			if err != nil {
				t.Fatal("Something wrong when fetching genesis block")
			}
			assert.Equal(t, sb.Data, listBlocks[0].Data)

			sb, err = clientSkip.SendGetLatestBlock(elVNs, listBlocks[0])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			sbRepeat, err := clientSkip.SendGetLatestBlock(elVNs, listBlocks[2])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			assert.Equal(t, sb.Data, sbRepeat.Data)
		}

		queryMean := false
		for i, op := range operationList {
			if op == "mean" && i == 1 {
				queryMean = true
			}
		}

		// only check the blocks when testing all the operation (mean operation must be executed in 2nd place
		if queryMean {
			// check getting one random block
			sb, err := clientSkip.SendGetBlock(elVNs, "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' block:", err)
			}
			assert.Equal(t, sb.Data, listBlocks[1].Data)

			res, err := clientSkip.SendGetProofs(elVNs.List[0], "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' form the DB", err)
			}

			// just check if map is not empty
			assert.NotEmpty(t, res)
		}

		// close DB
		clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
	}
}

func TestServiceDrynxLogisticRegressionBC(t *testing.T) {
	//t.Skip("NOP")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)

	//------SET PARAMS--------

	proofs := 0 // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false

	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 3
	nbrVNs := 3
	repartition := []int64{1, 1, 1} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := 0

	// ---- simulation parameters -----
	numberTrials := 1
	// 0: train together, test together
	// 1: train together, test separate
	// 2: train separate, test separate
	standardisationMode := 0
	scale := 1e0


	// ---- BC dataset parameters ----
	BCinitweights := []float64{1.848370088551476,
		0.286239758738386, 0.08981923125470494, -0.18690706243407848, -0.3262679621485759, -0.004658059619875792,
		-0.06771852594642115, -0.03356854232955933, 0.36913770486411807, 0.10920691614787682, -0.10934780778503579,
		0.07476651226922847, 0.36970965023229635, -0.04466680762217592, 0.24573034220730391, -0.11982298425696375,
		-0.1726649096390212, 0.2285141934545088, 0.1103401010030876, -0.1353383207930743, 0.24974546813874446,
		0.32542381025542994, -0.01062641994239107, 0.03191927109868747, 0.1231617230698011, 0.495750349473766,
		0.174699277489005, -0.1294810005900508, 0.33278266140613083, 0.23383196826811523, -0.240202510121452,
		-0.11947639399175235, -0.057384385472992926, 0.3555721052366367, -0.11154683508136425, -0.2452371799330045,
		-0.4443183371532757, 0.25850388653143813, 0.013574466545007855, 0.12423650374156121, 0.36725801942294684,
		-0.11978092591093148, -0.011814329268178856, 0.23223817741401578, -0.017259809032768823, 0.31229826501374675,
		0.009841343747179255, -0.2308480195826556, 0.3935206315471663, 0.08304133930294014, -0.20129530498438997,
		0.07731657213452145, 0.24440860679620205, -0.22491096387583245, 0.13420331061774865, -0.15405015736847436,
		-0.07906762492267744, -0.1344444080968065, 0.5106681962737204, -0.048754014678640205, 0.15149311925529194,
		0.11611233329610764, -0.41083156501957185, 0.14467107635115886, -0.17442303561295153, -0.04674226700054208,
		0.3332110566496909, 0.02540116206260645, 0.070129906858633, -0.12823469225907405, 0.30742479886268514,
		-0.03434953234959304, 0.13643998993348294, 0.2079958054457693, 0.029418913992100098, 0.04456609002029264,
		-0.03205089316683408, -0.10654823590711081, -0.2660320282050501, -0.056159859877133074, 0.008419879168309368,
		-0.05558373416275095, -0.29555954778776183, 0.5030487962604395, -0.03685620414407571, -0.13675956698132,
		-0.03528122818637724, 0.07386670563662738, -0.07799282867720524, 0.11137045673580162, 0.2063481981534766,
		0.16728598318765117, 0.04322534995062402, 0.2543801966506651, 0.5085375175168044, 0.07270585568534323,
		0.11092331319569534, -0.2524445860751483, 0.03253185728512441, -0.09449075313430573, -0.1548520846443554}


	//*
	// middle result
	/*
	BCinitweights := []float64{1.7678564358780904,
		0.3132592806711221, 0.05123679904111379, -0.211006511471912, -0.336454378916358, 0.05447397588283442,
		-0.13378148815030416, -0.025122615577070077, 0.3985908650726176, 0.16543134903993278, -0.038478322039736876,
		0.044544000428805006, 0.5904158483405, -0.023883539839266082, 0.21733449518272344, -0.03859502161776531,
		-0.12001645192599923, 0.19594845081493675, 0.13779476914060157, -0.046315157262940214, 0.2183237553845953,
		0.44780967124197796, -0.032499157124520235, -0.04104381536145418, 0.15717521335871093, 0.44763526131268355,
		0.1485521203315279, -0.08260334971841123, 0.3918316483454583, 0.15934075475982182, -0.23493752609625923,
		-0.200443426942284, -0.09024461695428579, 0.34830921494681255, -0.05703430022910106, -0.20324110475898996,
		-0.3868835854272387, 0.28349060733651904, -0.01127954970344747, 0.17550396859614834, 0.414025733105834,
		-0.16184302699830858, 0.03727612036303281, 0.2078866150113124, -0.055671052760772555, 0.31619953545874335,
		0.0018207544153033088, -0.2237626116556003, 0.41354801301316063, 0.08207850668870376, -0.06854756298712485,
		0.07539062007277422, 0.2544361697891417, -0.1770762262882377, 0.2747363695512233, -0.04966570293050547,
		-0.12207873829569824, -0.1777849695585312, 0.553903680899237, -0.02822620152542268, 0.15440906249720784,
		0.09193628548103776, -0.38043299289530014, 0.07105028330102217, -0.1840891617092915, 0.07705241918752796,
		0.47668388442437337, -0.06661756217511824, 0.12709331412274766, -0.14418500693406824, 0.36634070037181626,
		-0.06783147336314624, 0.20113473878872545, 0.2151256882247086, 0.001554957482651289, 0.14677177530313015,
		-0.05021346669444275, -0.04857022325760648, -0.33551982135034286, -0.06109254490184663, 0.09592335548264425,
		-0.15748415191541962, -0.2892707851690166, 0.659746667067952, -0.10500013957844206, -0.09995635933608177,
		0.009234197927164643, -0.02819336600626385, 0.008430546523083443, 0.1780979299653693, 0.11000541642128922,
		0.14224243983753682, 0.09986336117224624, 0.1616071055343526, 0.5695679857308711, 0.07769462814000343,
		0.14182339703696617, -0.22746938705039316, 0.08911218324273486, -0.05435587711871381, -0.1077639945507261}

	 */

	/*
	// a not good final local minima
	BCinitweights := []float64{1.7115208396211532,
		0.09804344539048392, 0.30963110418350737, 0.4967334110231846, -0.15353977578926087, -0.4350077909394633,
		0.16076891407306781, -0.14221152006122426, 0.007963791680404092, 0.2752225340966251, -0.11088053743501176,
		0.36267428767092047, -0.08629587368935143, 0.32155865122248045, -0.2545497626115361, -0.2113361833706059,
		0.06746532877759231, -0.11769384529065292, 0.029477073284705894, -0.24081898197822793, 0.07697280458594383,
		0.20722458170606006, 0.1418028017834666, 0.2920948096454178, -0.2266158476094183, 0.5188710173394244,
		-0.2080113065995116, -0.1093896385402383, 0.6721868981975611, 0.20139883555781593, 0.46298473051153033,
		0.12111612968290668, -0.28856835108426176, 0.19428186539720618, -0.3769906034130692, 0.9081009984974028,
		0.1117642964447684, 0.02475902287319749, 0.3866347562282525, -0.14004596559395988, -0.27126314299084614,
		-0.05546879993442043, -0.39823622853806195, -0.026317703573272816, 0.1535473064394457, -0.03752062950338876,
		-0.07912320829028992, -0.5313288027332748, 0.2663143581382137, -0.15881925607270272, 0.5131109384036685,
		-0.09808076097404758, -0.382886334353289, 0.36614171603006335, 0.16461542057213535, -0.08967723353637211,
		-0.08894533424539038, -0.6553821619629254, -0.5033171833154536, -0.6255268570524627, -0.10911745594889843,
		0.1469450355408124, -0.3912543854095289, 0.056231261585926444, -0.23080457365669904, -0.4426030793809363,
		-0.128423110308115, 0.2886225357367721, 0.09827694027888774, -0.09198279014975394, -0.47116202593192896,
		0.21706903082500198, -0.15646653965155305, -0.37975445743177183, -0.04213798367528775, 0.3910878047329491,
		0.29440525214441554, 0.05120328642048394, 0.0416197567575079, 0.09084182366937081, 0.018407314731036052,
		-0.56581227234986, -0.16812782265375842, 0.024473467110893314, -0.6499443233281175, -0.010200641306524144,
		-0.38326883823275937, 0.12062211152978697, 0.07441169536548753, -0.19402181849157954, -0.24752650232185466,
		0.037185230634735195, -0.06839622019369669, 0.31165910707689715, 0.06619039800641713, -0.2371871547720122,
		-0.13054716798072996, 0.2272086497446085, 0.1970550089670653, 0.04188823481499862, 0.8779883846586765}

	 */
	fmt.Println("len of BCinitweights:", len(BCinitweights))
	dataset := "BC"
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1,
		Step: 0.1, MaxIterations:1000, InitialWeights: BCinitweights}
	lrParameters.DatasetName = "BC"
	//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	//*/

	//load the data
	filePathTraining := "../tmpdata/" + dataset + "_dataset_training.txt"
	filePathTesting := "../tmpdata/" + dataset + "_dataset_testing.txt"

	XTrain, _ := encoding.LoadData(dataset, filePathTraining)
	XTest, yTest := encoding.LoadData(dataset, filePathTesting)

	var means = make([]float64, 0)
	var standardDeviations = make([]float64, 0)
	if standardisationMode == 0 || standardisationMode == 1 {
		means = encoding.ComputeMeans(XTrain)
		standardDeviations = encoding.ComputeStandardDeviations(XTrain)
	} else {
		means = nil
		standardDeviations = nil
	}

	lrParameters.FilePath = filePathTraining
	lrParameters.NbrRecords = int64(len(XTrain))
	lrParameters.NbrFeatures = int64(len(XTrain[0]))
	lrParameters.Means = means
	lrParameters.StandardDeviations = standardDeviations

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	operationList := []string{"logistic regression"}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//------------------------

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}

	local := onet.NewLocalTest(cothority.Suite)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {

		// data providers data generation
		minGenerateData := 3
		maxGenerateData := 4
		dimensions := 5
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
		operation.LRParameters = lrParameters
		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)

		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {
			ranges = nil
		}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
		//var modulo int
		//if cuttingFactor != 0 {
		//	modulo = operation.NbrOutput / cuttingFactor
		//}
		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// QUERY RECAP
		log.Lvl1("\n")
		log.Lvl1("#----- QUERY -----#")
		log.Lvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
			}
		}

		// query generation

		surveyID := "query-" + op

		sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

			wg = libunlynx.StartParallelize(1)
			go func(elVNs *onet.Roster) {
				defer wg.Done()

				err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
				if err != nil {
					log.Fatal("Error sending query to VNs:", err)
				}
			}(elVNs)
			libunlynx.EndParallelize(wg)

			wgProofs[i] = libunlynx.StartParallelize(1)
			go func(index int, si *network.ServerIdentity) {
				defer wgProofs[index].Done()

				sb, err := clientSkip.SendEndVerification(si, surveyID)
				if err != nil {
					log.Fatal("Error starting the 'waiting' threads:", err)
				}
				listBlocks[index] = sb
			}(i, elVNs.List[0])
		}

		// send query and receive results
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}
		if len(*aggr) != 0 {
			weights := (*aggr)[0]
			if standardisationMode == 1 || standardisationMode == 2 {
				means = nil
				standardDeviations = nil
			}
			accuracy, precision, recall, fscore, auc := performanceEvaluation(weights, XTest, yTest, means, standardDeviations)

			meanAccuracy += accuracy
			meanPrecision += precision
			meanRecall += recall
			meanFscore += fscore
			meanAUC += auc
		}
	}

	meanAccuracy /= float64(numberTrials)
	meanPrecision /= float64(numberTrials)
	meanRecall /= float64(numberTrials)
	meanFscore /= float64(numberTrials)
	meanAUC /= float64(numberTrials)

	fmt.Println("Final evaluation over", numberTrials, "trials")
	fmt.Println("accuracy: ", meanAccuracy)
	fmt.Println("precision:", meanPrecision)
	fmt.Println("recall:   ", meanRecall)
	fmt.Println("F-score:  ", meanFscore)
	fmt.Println("AUC:      ", meanAUC)
	fmt.Println()
	log.Lvl1("ICI")
	//encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	if proofs != 0 {
		clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip")
		for _, wg := range wgProofs {
			libunlynx.EndParallelize(wg)
		}

		// check genesis block
		if len(listBlocks) > 2 {
			sb, err := clientSkip.SendGetGenesis(elVNs.List[0])
			if err != nil {
				t.Fatal("Something wrong when fetching genesis block")
			}
			assert.Equal(t, sb.Data, listBlocks[0].Data)

			sb, err = clientSkip.SendGetLatestBlock(elVNs, listBlocks[0])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			sbRepeat, err := clientSkip.SendGetLatestBlock(elVNs, listBlocks[2])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			assert.Equal(t, sb.Data, sbRepeat.Data)
		}

		queryMean := false
		for i, op := range operationList {
			if op == "mean" && i == 1 {
				queryMean = true
			}
		}

		// only check the blocks when testing all the operation (mean operation must be executed in 2nd place
		if queryMean {
			// check getting one random block
			sb, err := clientSkip.SendGetBlock(elVNs, "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' block:", err)
			}
			assert.Equal(t, sb.Data, listBlocks[1].Data)

			res, err := clientSkip.SendGetProofs(elVNs.List[0], "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' form the DB", err)
			}

			// just check if map is not empty
			assert.NotEmpty(t, res)
		}

		// close DB
		clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
	}
}

func TestServiceDrynxLogisticRegressionGSE(t *testing.T) {
	//t.Skip("NOP")
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)

	//------SET PARAMS--------

	proofs := 0 // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false

	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 3
	nbrVNs := 3
	repartition := []int64{1, 1, 1} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := 0

	// ---- simulation parameters -----
	numberTrials := 1
	// 0: train together, test together
	// 1: train together, test separate
	// 2: train separate, test separate
	standardisationMode := 0
	scale := 1e0

	// ---- GSE dataset parameters ----
	//*

	/* read weights from previous iteration */

	GSEinitweights := []float64{0.5902771172104568, -0.04127670728183489, -0.3202570024805373, 0.2754812131718989, 0.9187912690080765, 0.11130131548759904,
		-0.0717050223995385, 0.11146109877794093, -0.2071813775796026, 0.1896857053528938, 0.16959003401912864,
		0.6483701492303567, -0.02128715282150293, 0.15223491249017054, -0.23556757833970215, -0.1844718473382679,
		-0.5185194620795881, -0.02404538777342949, -0.10024593103635117, 0.2565902661809779, -0.039303672182917256,
		-0.2257186760153665, 0.1827087531260299, 0.6858930990672345, 0.1068445190052582, 0.1378433401188839,
		0.04180618261869623, 0.2592533884048236, 0.021068204132890834, -0.18882156453879306, 0.0742301110200974,
		-0.4457014759065601, 0.2443360219291286, -0.25183022420625045, -0.31966606557467536, 0.08088511316844227,
		-0.19403502618290855, -0.40384953193534984, 0.8005004072087792, -0.19759477342168327, -0.7291511480955835,
		-0.0751633247971401, -0.07056788721679949, 0.04575034522519528, 0.006050641213402584, -0.1754377619726308,
		0.008501251483287757, 0.5338962783432964, 0.3345148382862146, -0.24325304190184832, 0.6511955591362222,
		0.2907192679017982, -0.1663861124513035, 0.36135594855940745, -0.22160516791190893, -0.32190440013823873,
		0.26200349450357485, -0.26108184943168705, 0.5016652278751215, -0.26303469731556134, -0.28429910276559456,
		-0.5751119598777159, -0.5816912893942906, 0.352512077266896, -0.3852726925626071, -0.4379446296225263,
		-0.4937607509962222, -0.19082040367427833, 0.3289875055251721, 0.1460862401758255, 0.30909368615980304,
		0.13952196512039453, 0.25663630715476343, -0.08422852543465463, 0.2551261289148332, 0.10027148445633227,
		0.9091636451814827, -0.1445147964927266, 0.04843955373684375, -0.05895336653559663, -0.20553574398667618,
		-0.17491501522704786, -0.33488202397090455, -0.0752613606876575, -0.25698017957352576, -0.44563129371119375,
		-0.0624915348069571, -0.4480731007278441, 0.18810730911369772, -0.41503580274712576, 0.4562046424714234,
		-0.06674513285360575, 0.09973405995159954, 0.1087583975376056, -0.39689131201114425, 0.015665337806655757,
		-0.2958614169581974, -0.2943639916094213, 0.36912043995298993, -0.4388214223782673, 0.33604394934469867}

	fmt.Println("len of GSEinitweights:", len(GSEinitweights))
	dataset := "GSE"
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.01, MaxIterations: 400, InitialWeights: GSEinitweights}
	lrParameters.DatasetName = "GSE"
	//diffP = libdrynx.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	//*/

	//load the data
	filePathTraining := "../tmpdata/" + dataset + "_dataset_training.txt"
	filePathTesting := "../tmpdata/" + dataset + "_dataset_testing.txt"

	XTrain, _ := encoding.LoadData(dataset, filePathTraining)
	XTest, yTest := encoding.LoadData(dataset, filePathTesting)

	var means = make([]float64, 0)
	var standardDeviations = make([]float64, 0)
	if standardisationMode == 0 || standardisationMode == 1 {
		means = encoding.ComputeMeans(XTrain)
		standardDeviations = encoding.ComputeStandardDeviations(XTrain)
	} else {
		means = nil
		standardDeviations = nil
	}

	lrParameters.FilePath = filePathTraining
	lrParameters.NbrRecords = int64(len(XTrain))
	lrParameters.NbrFeatures = int64(len(XTrain[0]))
	lrParameters.Means = means
	lrParameters.StandardDeviations = standardDeviations

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	operationList := []string{"logistic regression"}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//------------------------

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}

	local := onet.NewLocalTest(cothority.Suite)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {

		// data providers data generation
		minGenerateData := 3
		maxGenerateData := 4
		dimensions := 5
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)
		operation.LRParameters = lrParameters
		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)

		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {
			ranges = nil
		}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
		//var modulo int
		//if cuttingFactor != 0 {
		//	modulo = operation.NbrOutput / cuttingFactor
		//}
		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {
			ps = nil
		}

		// QUERY RECAP
		log.Lvl1("\n")
		log.Lvl1("#----- QUERY -----#")
		log.Lvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.Lvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.Lvl1("No input range validation")
		} else {
			log.Lvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.Lvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.Lvl1(" no differential privacy")
		}
		log.Lvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.ServicePublic(services.ServiceName)
			}
		}

		// query generation

		surveyID := "query-" + op

		sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

			wg = libunlynx.StartParallelize(1)
			go func(elVNs *onet.Roster) {
				defer wg.Done()

				err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
				if err != nil {
					log.Fatal("Error sending query to VNs:", err)
				}
			}(elVNs)
			libunlynx.EndParallelize(wg)

			wgProofs[i] = libunlynx.StartParallelize(1)
			go func(index int, si *network.ServerIdentity) {
				defer wgProofs[index].Done()

				sb, err := clientSkip.SendEndVerification(si, surveyID)
				if err != nil {
					log.Fatal("Error starting the 'waiting' threads:", err)
				}
				listBlocks[index] = sb
			}(i, elVNs.List[0])
		}

		// send query and receive results
		grp, aggr, err := client.SendSurveyQuery(sq)

		if err != nil {
			t.Fatal("'Drynx' service did not start.", err)
		}

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			t.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				log.Lvl1((*grp)[i], ": ", v)
			}
		}
		if len(*aggr) != 0 {
			weights := (*aggr)[0]
			if standardisationMode == 1 || standardisationMode == 2 {
				means = nil
				standardDeviations = nil
			}
			accuracy, precision, recall, fscore, auc := performanceEvaluation(weights, XTest, yTest, means, standardDeviations)

			meanAccuracy += accuracy
			meanPrecision += precision
			meanRecall += recall
			meanFscore += fscore
			meanAUC += auc
		}
	}

	meanAccuracy /= float64(numberTrials)
	meanPrecision /= float64(numberTrials)
	meanRecall /= float64(numberTrials)
	meanFscore /= float64(numberTrials)
	meanAUC /= float64(numberTrials)

	fmt.Println("Final evaluation over", numberTrials, "trials")
	fmt.Println("accuracy: ", meanAccuracy)
	fmt.Println("precision:", meanPrecision)
	fmt.Println("recall:   ", meanRecall)
	fmt.Println("F-score:  ", meanFscore)
	fmt.Println("AUC:      ", meanAUC)
	fmt.Println()
	log.Lvl1("ICI")
	//encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	if proofs != 0 {
		clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip")
		for _, wg := range wgProofs {
			libunlynx.EndParallelize(wg)
		}

		// check genesis block
		if len(listBlocks) > 2 {
			sb, err := clientSkip.SendGetGenesis(elVNs.List[0])
			if err != nil {
				t.Fatal("Something wrong when fetching genesis block")
			}
			assert.Equal(t, sb.Data, listBlocks[0].Data)

			sb, err = clientSkip.SendGetLatestBlock(elVNs, listBlocks[0])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			sbRepeat, err := clientSkip.SendGetLatestBlock(elVNs, listBlocks[2])
			if err != nil {
				t.Fatal("Something wrong when fetching the last block")
			}

			assert.Equal(t, sb.Data, sbRepeat.Data)
		}

		queryMean := false
		for i, op := range operationList {
			if op == "mean" && i == 1 {
				queryMean = true
			}
		}

		// only check the blocks when testing all the operation (mean operation must be executed in 2nd place
		if queryMean {
			// check getting one random block
			sb, err := clientSkip.SendGetBlock(elVNs, "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' block:", err)
			}
			assert.Equal(t, sb.Data, listBlocks[1].Data)

			res, err := clientSkip.SendGetProofs(elVNs.List[0], "query-mean")
			if err != nil {
				t.Fatal("Something wrong when fetching the 'query-mean' form the DB", err)
			}

			// just check if map is not empty
			assert.NotEmpty(t, res)
		}

		// close DB
		clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
	}
}