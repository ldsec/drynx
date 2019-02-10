package main

import (
	"errors"
	"fmt"
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
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"math/rand"
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
	if err != nil {log.Fatal(err)}

	group.Save(publicTomlPath)
	return nil
}

func openGroupToml(tomlFileName string) (*onet.Roster, error) {
	f, err := os.Open(tomlFileName)
	if err != nil {return nil, err}
	el, err := app.ReadGroupDescToml(f)
	if err != nil {return nil, err}
	if len(el.Roster.List) <= 0 {return nil, errors.New("Empty or invalid drynx group file:" + tomlFileName)}
	return el.Roster, nil
}

// BEGIN CLIENT: QUERIER ----------

// RunDrynx runs a query
func RunDrynx(c *cli.Context) error {
	scriptPopulateDB := "./insertDB.py"
	dbLocation := "./Stats.db"

	elServers, _ := openGroupToml("test/groupServers.toml")
	elDPs, _ := openGroupToml("test/groupDPs.toml")
	log.LLvl1(elDPs)
	elVNs, _ := openGroupToml("test/groupVNs.toml")

	rangeProofs := false
	diffPri := false
	diffPriOpti := false
	//repartition: server1: 1 DP, server2: 1 DP, server3: 1 DP
	repartition := []int64{1, 1, 1}

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
	if proofs == int64(1) {rangeProofs = true} else {elVNs = nil}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
	//if proofs == int64(0) {thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}}
	if proofs == int64(1) {
		thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
	} else {thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}}

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
		operationList = []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg", "union", "inter", "logreg"}
	} else {operationList = []string{operationQuery}}

	dpToServers := services.RepartitionDPs(elServers, elDPs, repartition)
	log.LLvl1("JOHNNN", dpToServers)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	numberTrials := 1
	//kfold := int64(4)

	var wgProofs []*sync.WaitGroup
	if proofs == int64(1) {
		//wgProofs = make([]*sync.WaitGroup, kfold * int64(numberTrials))
		wgProofs = make([]*sync.WaitGroup, int64(numberTrials))
		}

	// ---- dataset parameters ----
	dataset := "CSV"
	ratio := 0.8
	scale := 1e0
	lrParameters := libdrynx.LogisticRegressionParameters{K: 2, PrecisionApproxCoefficients: scale, Lambda: 1.0, Step: 0.1, MaxIterations: 25,
		InitialWeights: []float64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, NbrDps: int64(len(dpsUsed))}
	//diffP = common.QueryDiffP{LapMean:0.0, LapScale:30.0, NoiseListSize: 90, Quanta: 0.0, Scale:scale, Limit:60}

	// create the filenames
	//JS
	filePathTraining := "/Users/jstephan/Desktop/dataset_training.txt"
	filePathTesting := "/Users/jstephan/Desktop/dataset_testing.txt"

	for _, op := range operationList {
		if op != "logreg" {
			start := time.Now()
			queryAnswer := ""

			//The number of dimensions is exactly the number of attributes - 1
			dimensions := int64(len(strings.Split(queryAttributes, ",")) - 1)
			operation := libdrynx.ChooseOperation(op, queryAttributes, queryMin, queryMax, dimensions, cuttingFactor, lrParameters)

			// define the number of groups for groupBy (1 per default)
			dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, Source: 1, GenerateDataMin: queryMin, GenerateDataMax: queryMax}

			// define the ranges for the input validation (1 range per data provider output)
			u := int64(16)
			l := int64(7)

			if rangeProofs {
				if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
					u = int64(0)
					l = int64(0)
				} else {
					u = int64(16)
					l = int64(8)
				}
			}

			ranges := make([]*[]int64, operation.NbrOutput)
			if rangeProofs {for i := range ranges {ranges[i] = &[]int64{u, l}}} else {ranges = nil}

			// choose if differential privacy or not, no diffP by default
			// choosing the limit is done by drawing the curve (e.g. wolframalpha)
			diffP := libdrynx.QueryDiffP{}
			if diffPri {
				diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1, Optimized: diffPriOpti}
			} else {diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0, Optimized: diffPriOpti}}

			// DPs signatures for Input Range Validation
			ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))

			if ranges != nil && u != int64(0) && l != int64(0) {
				for i := range elServers.List {
					temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
					for j := 0; j < len(ranges); j++ {temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0])}
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
			if proofs == int64(1) {for _, v := range elVNs.List {idToPublic[v.String()] = v.Public}}

			// query generation
			surveyID := "query-" + op
			sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation,
				ranges, ps, proofs, false, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor, dpsUsed)
			if !libdrynx.CheckParameters(sq, diffPri) {log.Fatal("Oups!")}

			var wg *sync.WaitGroup
			if proofs == int64(1) {
				// send query to the skipchain and 'wait' for all proofs' verification to be done
				clientSkip := services.NewDrynxClient(elVNs.List[0], "test-skip-"+op)

				wg = libunlynx.StartParallelize(1)
				go func(elVNs *onet.Roster) {
					defer wg.Done()
					err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
					if err != nil {log.Fatal("Error sending query to VNs:", err)}
				}(elVNs)
				libunlynx.EndParallelize(wg)

				wg = libunlynx.StartParallelize(1)
				go func(si *network.ServerIdentity) {
					defer wg.Done()
					block, err := clientSkip.SendEndVerification(si, surveyID)
					if err != nil {log.Fatal("Error starting the 'waiting' threads:", err)}
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
					for j := range v {queryAnswer += strconv.FormatFloat(v[j], 'f', 6, 64) + ", "}
				}
				queryAnswer = strings.TrimSuffix(queryAnswer, ", ")
			}
			log.LLvl1("Operation " + op + " is done successfully.")

			log.LLvl1("Query took", time.Since(start))

			//Store query answer in local database
			log.LLvl1("Update local database.")
			cmd := exec.Command("python", scriptPopulateDB, dbLocation, queryAnswer, strconv.Itoa(int(time.Now().Unix())),
				operation.NameOp, queryAttributes, dpsQuery, queryMinString, queryMaxString)
			_, err := cmd.Output()
			if err != nil {println(err.Error())}

			if proofs == int64(1) {
				clientSkip := services.NewDrynxClient(elVNs.List[0], "close-DB")
				libunlynx.EndParallelize(wg)
				// close DB
				clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
			}
		} else {
			start := time.Now()

			// ---- simulation parameters -----
			//initSeed := int64(rand.Intn(5432109876))
			// 0: train together, test together
			// 1: train together, test separate
			// 2: train separate, test separate
			standardisationMode := 2

			// choose if differential privacy or not, no diffP by default
			diffP := libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0}
			// to activate

			meanAccuracy := 0.0
			meanPrecision := 0.0
			meanRecall := 0.0
			meanFscore := 0.0
			meanAUC := 0.0

			log.LLvl1("Simulating homomorphism-aware logistic regression for the " + dataset + " dataset")

			// load the dataset
			surveyNumber := int64(0)
			for trial := 0; trial < numberTrials; trial++ {
				//JS
				filepath := "/Users/jstephan/Desktop/Swisscom/LogisticRegression/temp/total22_final_" + strconv.Itoa(trial) + ".csv"
				//filepath2 := "/root/temp/total22_final_" + strconv.Itoa(trial) + ".csv"
				X, y := encoding2.LoadData(dataset, filepath)

				log.LLvl1("Evaluating prediction on dataset for trial:", trial)

				// split into training and testing set
				//seed := initSeed + int64(i)
				seed := rand.Int63n(5432109876)
				//seed := int64(rand.Intn(5432109876))
				XTrain, yTrain, XTest, yTest := encoding2.PartitionDataset(X, y, ratio, true, seed)

				//for partition := int64(0); partition < kfold; partition++ {
				//	XTrain, yTrain, XTest, yTest := encoding2.PartitionDatasetCV(X, y, partition, kfold)

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

					//JS
					// lrParameters.FilePath = filePathTraining
					lrParameters.FilePath = filepath
					//lrParameters.FilePath = filepath2
					lrParameters.NbrRecords = int64(len(trainingSet))
					lrParameters.NbrFeatures = int64(len(XTrain[0]))
					lrParameters.Means = means
					lrParameters.StandardDeviations = standardDeviations
					operation := libdrynx.ChooseOperation(op, "", 0, 0, 0, cuttingFactor, lrParameters)
					dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateDataMin: queryMin, GenerateDataMax: queryMax}

					// define the ranges for the input validation (1 range per data provider output)
					u := int64(4)
					l := int64(6)

					ranges := make([]*[]int64, operation.NbrOutput)
					if rangeProofs {for i := range ranges {ranges[i] = &[]int64{u, l}}} else {ranges = nil}

					// DPs signatures for Input Range Validation
					ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))

					if ranges != nil && u != int64(0) && l != int64(0) {
						for i := range elServers.List {
							temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
							for j := 0; j < len(ranges); j++ {temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0])}
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
					if proofs == int64(1) {for _, v := range elVNs.List {idToPublic[v.String()] = v.Public}}

					thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch
					// query sending + results receiving
					cuttingFactor := int64(0)

					//surveyID := "query-" + op + "-" + strconv.Itoa(queryIndex)
					surveyID := "query_" + strconv.FormatInt(surveyNumber,10) + "-" + op
					sq := client.GenerateSurveyQuery(elServers, elVNs, dpToServers, idToPublic, surveyID, operation,
						ranges, ps, proofs, false, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor, dpsUsed)

					//log.LLvl1("SENT QUERY", int64(trial) * kfold + partition)

					if proofs == int64(1) {
						// send query to the skipchain and 'wait' for all proofs' verification to be done
						clientSkip := services.NewDrynxClient(elVNs.List[0], "skip_" + strconv.FormatInt(surveyNumber,10) + "-" + op)

						var wg *sync.WaitGroup
						wg = libunlynx.StartParallelize(1)
						go func(elVNs *onet.Roster) {
							defer wg.Done()
							err := clientSkip.SendSurveyQueryToVNs(elVNs, &sq)
							if err != nil {log.Fatal("Error sending query to VNs:", err)}
						}(elVNs)
						libunlynx.EndParallelize(wg)

						proofIndex := int(surveyNumber)
						wgProofs[proofIndex] = libunlynx.StartParallelize(1)
						go func(index int, si *network.ServerIdentity, sID string) {
							defer wgProofs[index].Done()
							_, err := clientSkip.SendEndVerification(si, sID)
							if err != nil {log.Fatal("Error starting the 'waiting' threads:", err)}
						}(proofIndex, elVNs.List[0], surveyID)
					}

					_, aggr, _ := client.SendSurveyQuery(sq)
					if len(*aggr) != 0 {
						weights := (*aggr)[0]
						if standardisationMode == 1 || standardisationMode == 2 {
							means = nil
							standardDeviations = nil
						}

						accuracyTemp, precisionTemp, recallTemp, fscoreTemp, aucTemp := services.PerformanceEvaluation(weights, XTest, yTest, means, standardDeviations)

						meanAccuracy += accuracyTemp
						meanPrecision += precisionTemp
						meanRecall += recallTemp
						meanFscore += fscoreTemp
						meanAUC += aucTemp
						}

						fileTraining.Close()
						fileTesting.Close()
						surveyNumber++

			}

			meanAccuracy /= float64(int64(numberTrials))// * kfold)
			meanPrecision /= float64(int64(numberTrials))// * kfold)
			meanRecall /= float64(int64(numberTrials))// * kfold)
			meanFscore /= float64(int64(numberTrials))// * kfold)
			meanAUC /= float64(int64(numberTrials))// * kfold)

			fmt.Println("Final evaluation over", numberTrials, "trials")
			fmt.Println("accuracy: ", meanAccuracy)
			fmt.Println("precision:", meanPrecision)
			fmt.Println("recall:   ", meanRecall)
			fmt.Println("F-score:  ", meanFscore)
			fmt.Println("AUC:      ", meanAUC)

			if proofs == int64(1) {
				clientSkip := services.NewDrynxClient(elVNs.List[0], "closeDB")
				for _, wg := range wgProofs {libunlynx.EndParallelize(wg)}
				// close DB
				clientSkip.SendCloseDB(elVNs, &libdrynx.CloseDB{Close: 1})
			}

			log.LLvl1("Logistic Regression operation took", time.Since(start))
		}

	}
	log.LLvl1("All done.")
	return nil
}

// CLIENT END: QUERIER ----------