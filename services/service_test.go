package services

import (
	"fmt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/satori/go.uuid.v1"
	"math"
	"os"
	"strconv"
	"sync"
	"testing"
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
	//------SET PARAMS--------

	proofs := int64(0) // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false
	diffPriOpti := false
	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 5
	nbrVNs := 0
	repartition := []int64{2, 1, 2} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := int64(0)

	//operationList := []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg", "union", "inter"}
	operationList := []string{"mean"}
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

	local := onet.NewLocalTest(libunlynx.SuiTe)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	//Create dpToServers manually based on the group tomls
	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {
		// data providers data generation
		minGenerateData := int64(3)
		maxGenerateData := int64(4)
		dimensions := int64(5)
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
		log.LLvl1("\n")
		log.LLvl1("#----- QUERY -----#")
		log.LLvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.LLvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.LLvl1("No input range validation")
		} else {
			log.LLvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.LLvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.LLvl1(" no differential privacy")
		}
		log.LLvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.Public
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.Public
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.Public
			}
		}

		// query generation

		surveyID := "query-" + op
		sq := client.GenerateSurveyQuery(elServers, nil, dpToServers, idToPublic, surveyID, operation, ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor)
		if !libdrynx.CheckParameters(sq, diffPri) {
			log.Fatal("Oups!")
		}

		var wg *sync.WaitGroup
		if proofs != 0 {
			// send query to the skipchain and 'wait' for all proofs' verification to be done
			clientSkip := NewDrynxClient(elVNs.List[0], "test-skip-"+op)

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
				log.LLvl1((*grp)[i], ": ", v, v[0])
			}

			log.LLvl1((*aggr)[0][0])
		}
	}

	if proofs != 0 {
		clientSkip := NewDrynxClient(elVNs.List[0], "test-skip")
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
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)

	//------SET PARAMS--------

	proofs := int64(0) // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := true
	obfuscation := false

	diffPri := false

	nbrRows := int64(1)
	nbrServers := 3
	nbrDPs := 5
	nbrVNs := 3
	repartition := []int64{2, 1, 2} //repartition: server1: 1 DPs, server2: 1 DPs, server3: 1 DPs

	//simulation
	cuttingFactor := int64(0)

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

	local := onet.NewLocalTest(libunlynx.SuiTe)
	elServers, elDPs, elVNs := generateNodes(local, nbrServers, nbrDPs, nbrVNs)

	if proofs == 0 {
		elVNs = nil
	}
	defer local.CloseAll()

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := NewDrynxClient(elServers.List[0], "test-Drynx")

	var wgProofs []*sync.WaitGroup
	var listBlocks []*skipchain.SkipBlock
	if proofs != 0 {
		wgProofs = make([]*sync.WaitGroup, len(operationList))
		listBlocks = make([]*skipchain.SkipBlock, len(operationList))
	}

	for i, op := range operationList {
		// data providers data generation
		minGenerateData := int64(3)
		maxGenerateData := int64(4)
		dimensions := int64(5)
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
		log.LLvl1("\n")
		log.LLvl1("#----- QUERY -----#")
		log.LLvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.LLvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.LLvl1("No input range validation")
		} else {
			log.LLvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.LLvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.LLvl1(" no differential privacy")
		}
		log.LLvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {
			idToPublic[v.String()] = v.Public
		}
		for _, v := range elDPs.List {
			idToPublic[v.String()] = v.Public
		}

		if proofs != 0 {
			for _, v := range elVNs.List {
				idToPublic[v.String()] = v.Public
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
			clientSkip := NewDrynxClient(elVNs.List[0], "test-skip-"+op)

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
				log.LLvl1((*grp)[i], ": ", v)
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
	log.LLvl1("ICI")
	//encoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	if proofs != 0 {
		clientSkip := NewDrynxClient(elVNs.List[0], "test-skip")
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
	local := onet.NewLocalTest(libunlynx.SuiTe)
	local1 := onet.NewLocalTest(libunlynx.SuiTe)
	local2 := onet.NewLocalTest(libunlynx.SuiTe)

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

	proofs := int64(0) // 0 is not proof, 1 is proofs, 2 is optimized proofs

	defer local.CloseAll()

	// Create a client (querier) for the service)
	client := NewDrynxClient(el.List[0], strconv.Itoa(0))

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
	dataset := "PCS"
	ratio := 0.8
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
		InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0}}
	//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}

	// ---- Pima dataset parameters ----
	/*
		dataset := "Pima"
		ratio := 0.75
		lrParameters := common.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.1, MaxIterations: 200, InitialWeights: []float64{0.334781, -0.633628, 0.225721, -0.648192, 0.406207,
		0.044424, -0.426648, 0.877499, -0.426819}}
		diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// ---- SPECTF dataset parameters ----
	/*
		dataset := "SPECTF"
		ratio := 0.3
		lrParameters := common.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0,
		Step: 0.012, MaxIterations: 450, InitialWeights: []float64{
					0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
					0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
					-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
					0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
					-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}}
		//diffP = common.QueryDiffP{LapMean:0.0, LapScale:15.0, NoiseListSize: 2070, Quanta: 0.0, Scale:scale, Limit:60}
	*/

	// ---- LBW dataset parameters ----
	/*
		dataset := "LBW"
		ratio := 0.8
		lrParameters := common.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
			InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
		//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 110, Quanta: 0.0, Scale:scale, Limit:60}
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

	log.LLvl1("Simulating homomorphism-aware logistic regression for the " + dataset + " dataset")
	fmt.Println(filepath)

	// load the dataset
	X, y := encoding.LoadData(dataset, filepath)

	for i := 0; i < numberTrials; i++ {
		log.LLvl1("Evaluating prediction on dataset for trial:", i)

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
		log.LLvl1("Service Drynx Test with suite: ", libunlynx.SuiTe.String(), " and query:")
		log.LLvl1("SELECT ", operation, " ... FROM DP0, ..., DP", len(el1.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil {
			log.LLvl1("No input range validation")
		} else {
			log.LLvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.LLvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		}

		idToPublic := make(map[string]kyber.Point)
		for _, v := range el.List {
			idToPublic[v.String()] = v.Public
		}
		for _, v := range el1.List {
			idToPublic[v.String()] = v.Public
		}
		for _, v := range elVNs.List {
			idToPublic[v.String()] = v.Public
		}

		thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
		// query sending + results receiving
		cuttingFactor := int64(0)
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
				log.LLvl1((*grp)[i], ": ", v)
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
