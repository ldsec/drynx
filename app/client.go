package main

import (
	"fmt"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	encoding2 "github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/services"
	//services2 "github.com/lca1/drynx/services"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BEGIN SERVER: DP or COMPUTING NODE ----------

// NonInteractiveSetup is used to setup the cothority node for unlynx in a non-interactive way (and without error checks)
func NonInteractiveSetup(c *cli.Context) error {
	// cli arguments
	serverBindingStr := c.String("serverBinding")
	description := c.String("description")
	privateTomlPath := c.String("privateTomlPath")
	publicTomlPath := c.String("publicTomlPath")

	if serverBindingStr == "" || description == "" || privateTomlPath == "" || publicTomlPath == "" {
		err := errors.New("arguments not OK")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	kp := key.NewKeyPair(libunlynx.SuiTe)

	privStr, _ := encoding.ScalarToStringHex(libunlynx.SuiTe, kp.Private)
	pubStr, _ := encoding.PointToStringHex(libunlynx.SuiTe, kp.Public)
	public, _ := encoding.StringHexToPoint(libunlynx.SuiTe, pubStr)

	//serverBinding := network.NewTLSAddress(serverBindingStr)
	serverBinding := network.NewTCPAddress(serverBindingStr)
	conf := &app.CothorityConfig{
		Suite:       libunlynx.SuiTe.String(),
		Public:      pubStr,
		Private:     privStr,
		Address:     serverBinding,
		Description: description,
	}

	server := app.NewServerToml(libunlynx.SuiTe, public, serverBinding, conf.Description)
	group := app.NewGroupToml(server)

	err := conf.Save(privateTomlPath)
	if err != nil {
		log.Fatal(err)
	}

	group.Save(publicTomlPath)
	return nil
}

func openGroupToml(tomlFileName string) (*onet.Roster, error) {
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupDescToml(f)
	if err != nil {
		return nil, err
	}
	if len(el.Roster.List) <= 0 {
		return nil, errors.New("Empty or invalid drynx group file:" + tomlFileName)
	}
	return el.Roster, nil
}

// BEGIN CLIENT: QUERIER ----------
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

func PerformanceEvaluation(weights []float64, XTest [][]float64, yTest []int64, means []float64,
	standardDeviations []float64) (float64,
	float64, float64, float64, float64) {
	fmt.Println("weights:", weights)

	if means != nil && standardDeviations != nil &&
		len(means) > 0 && len(standardDeviations) > 0 {
		// using global means and standard deviations, if given
		log.Lvl1("Standardising the testing set with global means and standard deviations...")
		XTest = encoding2.StandardiseWith(XTest, means, standardDeviations)
	} else {
		// using local means and standard deviations, if not given
		log.Lvl1("Standardising the testing set with local means and standard deviations...")
		XTest = encoding2.Standardise(XTest)
	}

	predictions := make([]int64, len(XTest))
	predictionsFloat := make([]float64, len(XTest))
	for i := range XTest {
		predictionsFloat[i] = encoding2.PredictInClear(XTest[i], weights)
		predictions[i] = int64(math.Round(predictionsFloat[i]))
		fmt.Printf("%12.8e %1d %2d\n", predictionsFloat[i], predictions[i], yTest[i])
	}

	//encoding.PointToStringHex()
	accuracy := encoding2.Accuracy(predictions, yTest)
	precision := encoding2.Precision(predictions, yTest)
	recall := encoding2.Recall(predictions, yTest)
	fscore := encoding2.Fscore(predictions, yTest)
	auc := encoding2.AreaUnderCurve(predictionsFloat, yTest)

	fmt.Println("accuracy: ", accuracy)
	fmt.Println("precision:", precision)
	fmt.Println("recall:   ", recall)
	fmt.Println("F-score:  ", fscore)
	fmt.Println("AUC:      ", auc)
	return accuracy, precision, recall, fscore, auc
}

// RunDrynx runs a query
func RunDrynx(c *cli.Context) error {
	scriptPopulateDB := "./insertDB.py"
	dbLocation := "./Stats.db"

	elServers, _ := openGroupToml("test/groupServers.toml")
	elDPs, _ := openGroupToml("test/groupDPs.toml")
	elVNs, _ := openGroupToml("test/groupVNs.toml")

	rangeProofs := false
	obfuscation := false

	diffPri := false
	diffPriOpti := false
	//repartition: server1: 1 DP, server2: 1 DP, server3: 1 DP
	repartition := []int64{1, 1, 1}
	//repartition (Real Scenario): server1: 3 DPs, server2: 3 DPs, server3: 3 DPs
	//repartition := []int64{3, 3, 3}

	//simulation
	cuttingFactor := int64(0)

	//Get the query operation to be executed
	operationQuery := c.String("operation")

	//Get the attribute over which the query should be executed
	queryAttributes := c.String("attributes")

	//Get the query min and max values over which the query should be executed
	queryMinString := c.String("min")
	queryMaxString := c.String("max")
	queryMin, _ := strconv.ParseInt(queryMinString, 10, 64)
	queryMax, _ := strconv.ParseInt(queryMaxString, 10, 64)

	//Check whether or not proofs are enabled
	// 0 is not proof, 1 is proofs, 2 is optimized proofs
	proofs, _ := strconv.ParseInt(c.String("proofs"), 10, 64)
	if proofs == int64(1) {rangeProofs = true}

	//Get the DPs over which the query should be executed
	dpsQuery := c.String("dps")
	s := strings.Split(dpsQuery, ",")
	//DPs over which the query is executed
	dpsUsed := make([]*network.ServerIdentity, len(s))
	for i, indexString := range s {
		index, _ := strconv.Atoi(indexString)
		dpsUsed[i] = elDPs.List[index]
	}

	var operationList []string
	if operationQuery == "all" {
		operationList = []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg", "union", "inter"}
	} else {operationList = []string{operationQuery}}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch

	if proofs == 0 {elVNs = nil}

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}}

	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")


	//logistic regression parameters
	precision := 1e2
	// gradient descent parameters
	lambda := 1.0
	step := 0.001
	maxIterations := 100
	initialWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	lrParameters := libdrynx.LogisticRegressionParameters{FilePath: "/Users/jstephan/Desktop/temp/total22_final_99.csv", NbrRecords: 0,
	NbrFeatures: 0, NbrDps: int64(len(dpsUsed)), Lambda: lambda, Step: step, MaxIterations: int64(maxIterations),
	InitialWeights: initialWeights, K: 2, PrecisionApproxCoefficients: precision}

	for _, op := range operationList {

		if op != "logreg" {
			start := time.Now()

			queryAnswer := ""
			// data providers data fetch
			//The number of dimensions is exactly the number of attributes - 1
			dimensions := int64(len(strings.Split(queryAttributes, ",")) - 1)

			operation := libdrynx.ChooseOperation(op, queryAttributes, queryMin, queryMax, dimensions, cuttingFactor, lrParameters)

			// define the number of groups for groupBy (1 per default)
			dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateDataMin: queryMin, GenerateDataMax: queryMax}

			// define the ranges for the input validation (1 range per data provider output)
			var u, l int64
			uSmall := int64(16)
			lSmall := int64(7)

			if rangeProofs {
				if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
					if obfuscation {
						u = int64(2)
						l = int64(1)
					} else {
						u = int64(0)
						l = int64(0)
					}
				} else {
					obfuscation = false
					u = int64(16)
					l = int64(8)
				}
			}

			ranges := make([]*[]int64, operation.NbrOutput)
			if rangeProofs {
				//for i := range ranges {ranges[i] = &[]int64{u, l}}
				for i := range ranges {ranges[i] = &[]int64{uSmall, lSmall}}
			} else {ranges = nil}

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

			if ranges != nil && u != int64(0) && l != int64(0) {
				for i := range elServers.List {
					temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
					for j := 0; j < len(ranges); j++ {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
					ps[i] = &temp
				}
			} else {ps = nil}

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
			for _, v := range elServers.List {idToPublic[v.String()] = v.Public}
			for _, v := range elDPs.List {idToPublic[v.String()] = v.Public}
			if proofs != 0 {for _, v := range elVNs.List {idToPublic[v.String()] = v.Public}}

			// query generation
			surveyID := "query-" + op
			sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation,
				ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor, dpsUsed)
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

				wg = libunlynx.StartParallelize(1)
				go func(si *network.ServerIdentity) {
					defer wg.Done()

					block, err := clientSkip.SendEndVerification(si, surveyID)
					if err != nil {
						log.Fatal("Error starting the 'waiting' threads:", err)
					}
					log.LLvl1("Inserted new block", block)
				}(elVNs.List[0])
			}

			// send query and receive results
			log.LLvl1("Sending Query to Computing Nodes")
			grp, aggr, _ := client.SendSurveyQuery(sq)

			// Result printing
			if len(*grp) != 0 && len(*grp) != len(*aggr) {
				log.Fatal("Results format problem")
			} else {
				for i, v := range *aggr {
					log.LLvl1((*grp)[i], ": ", v)
					for j := range v {
						queryAnswer += strconv.FormatFloat(v[j], 'f', 6, 64) + ", "
					}
				}
				queryAnswer = strings.TrimSuffix(queryAnswer, ", ")
			}
			log.LLvl1("Operation " + op + " is done successfully.")

			elapsed := time.Since(start)
			log.LLvl1("Query took", elapsed)

			//Store query answer in local database
			log.LLvl1("Update local database.")
			cmd := exec.Command("python", scriptPopulateDB, dbLocation, queryAnswer, strconv.Itoa(int(time.Now().Unix())),
				operation.NameOp, queryAttributes, dpsQuery, queryMinString, queryMaxString)
			_, err := cmd.Output()
			if err != nil {
				println(err.Error())
			}

			if proofs != 0 {
				clientSkip := services.NewDrynxClient(elVNs.List[0], "close-DB")
				libunlynx.EndParallelize(wg)
				// close DB
				clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
			}
		} else {

			proofs := int64(0) // 0 is not proof, 1 is proofs, 2 is optimized proofs
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
			dataset := "CSV"
			ratio := 0.8
			lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
				InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, NbrDps: int64(len(dpsUsed))}
			//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}

			// create the filenames
			filepath := "/Users/jstephan/Desktop/temp/total22_final_99.csv"
			filePathTraining := "/Users/jstephan/Desktop/dataset_training.txt"
			filePathTesting := "/Users/jstephan/Desktop/dataset_testing.txt"

			meanAccuracy := 0.0
			meanPrecision := 0.0
			meanRecall := 0.0
			meanFscore := 0.0
			meanAUC := 0.0

			log.LLvl1("Simulating homomorphism-aware logistic regression for the " + dataset + " dataset")
			fmt.Println(filepath)

			// load the dataset
			X, y := encoding2.LoadData(dataset, filepath)

			for i := 0; i < numberTrials; i++ {
				log.LLvl1("Evaluating prediction on dataset for trial:", i)

				// split into training and testing set
				seed := initSeed + int64(i)
				XTrain, yTrain, XTest, yTest := encoding2.PartitionDataset(X, y, ratio, true, seed)

				// write to file
				trainingSet := encoding2.InsertColumn(XTrain, encoding2.Int64ToFloat641DArray(yTrain), 0)
				testingSet := encoding2.InsertColumn(XTest, encoding2.Int64ToFloat641DArray(yTest), 0)

				fileTraining, _ := os.Create(filePathTraining)
				fileTesting, _ := os.Create(filePathTesting)

				for i := 0; i < len(trainingSet); i++ {
					for j := 0; j < len(trainingSet[i])-1; j++ {
						_, _ = fileTraining.WriteString(fmt.Sprint(trainingSet[i][j]) + ",")
					}
					_, _ = fileTraining.WriteString(fmt.Sprintln(trainingSet[i][len(trainingSet[i])-1]))
				}

				for i := 0; i < len(testingSet); i++ {
					for j := 0; j < len(testingSet[i])-1; j++ {
						_, _ = fileTesting.WriteString(fmt.Sprint(testingSet[i][j]) + ",")
					}
					_, _ = fileTesting.WriteString(fmt.Sprintln(testingSet[i][len(testingSet[i])-1]))
				}

				var means = make([]float64, 0)
				var standardDeviations = make([]float64, 0)
				if standardisationMode == 0 || standardisationMode == 1 {
					means = encoding2.ComputeMeans(XTrain)
					standardDeviations = encoding2.ComputeStandardDeviations(XTrain)
				} else {
					means = nil
					standardDeviations = nil
				}

				lrParameters.FilePath = filePathTraining
				lrParameters.NbrRecords = int64(len(trainingSet))
				lrParameters.NbrFeatures = int64(len(XTrain[0]))
				lrParameters.Means = means
				lrParameters.StandardDeviations = standardDeviations
				operation := libdrynx.Operation{NameOp: "logreg", LRParameters: lrParameters}

				//dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{}, GenerateDataMin: minGenerateData, GenerateDataMax: maxGenerateData}
				dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateDataMin: queryMin, GenerateDataMax: queryMax}

				// define the ranges for the input validation (1 range per data provider output)
				u := int64(2)
				l := int64(6)

				ranges := make([]*[]int64, operation.NbrOutput)
				ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))
				for i := range ranges {ranges[i] = &[]int64{u, l}}
				// if no input validation
				//ranges = nil

				// signatures for Input Validation
				if !(ranges == nil) {
					for i := range elServers.List {
						temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
						for j := 0; j < len(ranges); j++ {
							temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
						}
						ps[i] = &temp
					}
				} else {ps = nil}

				// query parameters recap
				log.LLvl1("Service Drynx Test with suite: ", libunlynx.SuiTe.String(), " and query:")
				log.LLvl1("SELECT ", operation, " ... FROM DP0, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
				if ranges == nil {
					log.LLvl1("No input range validation")
				} else {log.LLvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")}
				if libdrynx.AddDiffP(diffP) {
					log.LLvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
				}

				idToPublic := make(map[string]kyber.Point)
				for _, v := range elServers.List {idToPublic[v.String()] = v.Public}
				for _, v := range elDPs.List {idToPublic[v.String()] = v.Public}
				if proofs != 0 {for _, v := range elVNs.List {idToPublic[v.String()] = v.Public}}

				thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
				// query sending + results receiving
				cuttingFactor := int64(0)

				surveyID := "query-" + op
				sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation,
					ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor, dpsUsed)

				_, aggr, _ := client.SendSurveyQuery(sq)

				if len(*aggr) != 0 {
					weights := (*aggr)[0]
					if standardisationMode == 1 || standardisationMode == 2 {
						means = nil
						standardDeviations = nil
					}

					accuracy, precision, recall, fscore, auc := PerformanceEvaluation(weights, XTest, yTest, means, standardDeviations)

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
		}

	}
	log.LLvl1("All done.")
	return nil
}

// CLIENT END: QUERIER ----------