package encoding_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/cdipaolo/goml/base"
	"github.com/cdipaolo/goml/linear"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/dedis/kyber/pairing/bn256"
)

type MinimisationParameters struct {
	// the logarithm function approximation degree
	k int
	// the regularization coefficient
	lambda float64
	// the learning rate
	step float64
	// the maximum number of iterations
	maxIterations int
	// the initial weights
	initialWeights []float64
}

func compareFindMinimumWeights(Xtrain [][]float64, ytrain []int64, parameters MinimisationParameters,
	preprocessing string, withEncryption bool, precisionApproxCoefficients float64, paperWeights []float64) {

	N := int64(len(Xtrain))
	k := parameters.k
	lambda := parameters.lambda
	step := parameters.step
	maxIterations := parameters.maxIterations
	initialWeights := parameters.initialWeights
	log.LLvl1(Xtrain)
	Xtrain = encoding.Standardise(Xtrain)
	Xtrain = encoding.Augment(Xtrain)
	// data providers part + servers part + client part collapsed here for testing

	var weights []float64
	var aggregatedApproxCoefficients [][]float64
	if withEncryption {
		// the clients (public key, private key) pair
		privKey, pubKey := libunlynx.GenKey()
		weights, aggregatedApproxCoefficients = findMinimumWeightsWithEncryption(Xtrain, ytrain, k, maxIterations,
			step, lambda, initialWeights, pubKey, privKey, precisionApproxCoefficients)
	} else {
		weights, aggregatedApproxCoefficients = findMinimumWeights(Xtrain, ytrain, k, maxIterations, step, lambda,
			initialWeights)
	}
	log.LLvl1(aggregatedApproxCoefficients)

	cost := encoding.Cost(weights, aggregatedApproxCoefficients, N, lambda)
	logisticCost := encoding.LogisticRegressionCost(weights, Xtrain, ytrain, N, lambda)

	fmt.Println("weights:", weights)
	fmt.Println("cost:", cost)
	fmt.Println("logistic cost:", logisticCost)
	fmt.Println()
	fmt.Println("Comparison with paper results")
	fmt.Println("cost:", encoding.Cost(paperWeights, aggregatedApproxCoefficients, N, lambda))
	fmt.Println("logistic cost:", encoding.LogisticRegressionCost(paperWeights, Xtrain, ytrain, N, lambda))
	fmt.Println()
}

func findMinimumWeights(X [][]float64, y []int64, k int, maxIterations int, step float64, lambda float64, initialWeights []float64) ([]float64, [][]float64) {

	// each data provider computes its approximation coefficients on its side and then sends them to its chosen server
	N := len(X)
	N_64 := int64(N)
	approxCoefficients := make([][][]float64, N)
	for i := range X {
		approxCoefficients[i] = encoding.ComputeAllApproxCoefficients(X[i], y[i], k)
	}
	aggregatedApproxCoefficients := encoding.AggregateApproxCoefficients(approxCoefficients)

	// the client computes the weights on its side
	weights := encoding.FindMinimumWeights(aggregatedApproxCoefficients,
		initialWeights, N_64,
		lambda, step, maxIterations)

	fmt.Println("weights 1", weights)
	return weights, aggregatedApproxCoefficients
}

func findMinimumWeightsWithEncryption(X [][]float64, y []int64, k int, maxIterations int, step float64, lambda float64,
	initialWeights []float64, pubKey kyber.Point, privKey kyber.Scalar,
	precisionApproxCoefficients float64) ([]float64, [][]float64) {

	// each data provider computes its approximation coefficients on its side, encrypts them,
	// and then sends them to its chosen server
	N := int64(len(X))

	approxCoefficients := make([][][]int64, N)

	encryptedApproxCoefficients := make([][]*libunlynx.CipherVector, N)
	for i := range X {
		approxCoefficients[i] = encoding.Float64ToInt642DArrayWithPrecision(
			encoding.ComputeAllApproxCoefficients(X[i], y[i], k),
			precisionApproxCoefficients)

		encryptedApproxCoefficients[i], _ = encoding.ComputeEncryptedApproxCoefficients(approxCoefficients[i], pubKey)
	}

	encryptedAggregatedApproxCoefficients := encoding.AggregateEncryptedApproxCoefficients(encryptedApproxCoefficients)

	weights, aggregatedApproxCoefficients := encoding.FindMinimumWeightsWithEncryption(
		encryptedAggregatedApproxCoefficients,
		privKey,
		initialWeights,
		N,
		lambda, step, maxIterations,
		precisionApproxCoefficients)

	return weights, aggregatedApproxCoefficients
}

func predict(Xtrain [][]float64, ytrain []int64,
	Xtest [][]float64, yTest []int64,
	weights []float64,
	parameters MinimisationParameters,
	preprocessing string, withEncryption bool,
	precisionApproxCoefficients float64, precisionData float64, precisionWeights float64) (float64,
	float64, float64, float64, float64) {

	k := parameters.k
	lambda := parameters.lambda
	step := parameters.step
	maxIterations := parameters.maxIterations
	initialWeights := parameters.initialWeights

	fmt.Println("init:", initialWeights)

	// save the original training set in order to standardise the testing set
	XtrainSaved := Xtrain

	// data pre-processing
	Xtrain = encoding.Standardise(Xtrain)
	Xtrain = encoding.Augment(Xtrain)

	// the client's (public key, private key) pair
	privKey, pubKey := libunlynx.GenKey()

	// data providers part + servers part + client part collapsed here for testing
	//var approxCoefficients [][]float64
	if weights == nil {
		if withEncryption {
			weights, _ = findMinimumWeightsWithEncryption(Xtrain,
				ytrain,
				k,
				maxIterations, step, lambda,
				initialWeights,
				pubKey, privKey,
				precisionApproxCoefficients)
		} else {
			weights, _ = findMinimumWeights(Xtrain,
				ytrain,
				k,
				maxIterations, step, lambda,
				initialWeights)
		}
	}
	fmt.Println("weights:", weights)
	//fmt.Println("approx:", approxCoefficients)

	// prediction computation
	// standardise the testing set using the mean and standard deviation of the training set
	if preprocessing == "standardize" {
		Xtest = encoding.StandardiseWithTrain(Xtest, XtrainSaved)
		//Xtest = encoding.Standardise(Xtest)
	} else if preprocessing == "normalize" {
		Xtest = encoding.NormalizeWith(Xtest, XtrainSaved)
	}
	// note: the test data does not need to be augmented with 1s

	predictions := make([]int64, len(Xtest))
	predictionsFloat := make([]float64, len(Xtest))
	if withEncryption {
		for i := range Xtest {
			encryptedData := libunlynx.EncryptIntVector(pubKey,
				encoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData))

			predictionsFloat[i] = encoding.PredictHomomorphic(*encryptedData,
				weights,
				privKey,
				precisionWeights, precisionData)

			predictions[i] = int64(math.Round(predictionsFloat[i])) //todo: define threshold parameter

			predict := encoding.Predict(*libunlynx.EncryptIntVector(pubKey,
				encoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData)),
				weights,
				privKey,
				precisionWeights, precisionData)

			predictHomomorphic := encoding.PredictHomomorphic(
				*libunlynx.EncryptIntVector(pubKey,
					encoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData)),
				weights,
				privKey,
				precisionWeights, precisionData)

			predictClear := encoding.PredictInClear(Xtest[i], weights)

			fmt.Printf("%12.8e %12.8e %12.8e %1d %2d\n", predictClear, predict, predictHomomorphic, predictions[i],
				yTest[i])
		}
	} else {
		for i := range Xtest {
			predictionsFloat[i] = encoding.PredictInClear(Xtest[i], weights)
			predictions[i] = int64(math.Round(predictionsFloat[i]))
			fmt.Printf("%12.8e %1d %2d\n", encoding.PredictInClear(Xtest[i], weights), predictions[i], yTest[i])
		}
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


	// compute the TPR (True Positive Rate) and FPR (False Positive Rate)
	//tpr, fpr := encoding.ComputeTPRFPR(predictionsFloat, yTest)
	// save to file (for plotting the ROC)
	//encoding.SaveToFile(tpr, "../../data/tpr.txt")
	//encoding.SaveToFile(fpr, "../../data/fpr.txt")


	return accuracy, precision, recall, fscore, auc
}

func predictWithRandomSplit(X [][]float64, y []int64, weights []float64,
	ratio float64, parameters MinimisationParameters, preprocessing string, precisionApproxCoefficients float64,
	precisionData float64, precisionWeights float64, withEncryption bool, numberTrials int, initSeed int64) {

	accuracy := make([]float64, numberTrials)
	precision := make([]float64, numberTrials)
	recall := make([]float64, numberTrials)
	fscore := make([]float64, numberTrials)
	auc := make([]float64, numberTrials)

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	for i := 0; i < numberTrials; i++ {
		seed := initSeed + int64(i)
		Xtrain, ytrain, Xtest, ytest := encoding.PartitionDataset(X, y, ratio, true, seed)

		fmt.Println("training set:", len(Xtrain))
		fmt.Println("testing set: ", len(Xtest))

		accuracy[i], precision[i], recall[i], fscore[i], auc[i] = predict(Xtrain, ytrain, Xtest, ytest, weights,
			parameters, preprocessing, withEncryption, precisionApproxCoefficients, precisionData, precisionWeights)

		meanAccuracy += accuracy[i]
		meanPrecision += precision[i]
		meanRecall += recall[i]
		meanFscore += fscore[i]
		meanAUC += auc[i]
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

func predictGoml(X [][]float64, y []int64, ratio float64, parameters MinimisationParameters, numberTrials int, initSeed int64) {

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	for i := 0; i < numberTrials; i++ {

		seed := initSeed + int64(i)
		Xtrain, ytrain, Xtest, ytest := encoding.PartitionDataset(X, y, ratio, true, seed)

		model := linear.NewLogistic(base.BatchGA, parameters.step, parameters.lambda, parameters.maxIterations, Xtrain, encoding.Int64ToFloat641DArray(ytrain))

		fmt.Println(model.Learn())

		predictions := make([]int64, len(Xtest))
		predictionsFloat := make([]float64, len(Xtest))
		for i := range Xtest {
			result, _ := model.Predict(Xtest[i], false)

			predictionsFloat[i] = result[0]
			predictions[i] = int64(math.Round(predictionsFloat[i]))
		}

		accuracy := encoding.Accuracy(predictions, ytest)
		precision := encoding.Precision(predictions, ytest)
		recall := encoding.Recall(predictions, ytest)
		fscore := encoding.Fscore(predictions, ytest)
		auc := encoding.AreaUnderCurve(predictionsFloat, ytest)

		fmt.Println("accuracy: ", accuracy)
		fmt.Println("precision:", precision)
		fmt.Println("recall:   ", recall)
		fmt.Println("F-score:  ", fscore)
		fmt.Println("AUC:      ", auc)
		fmt.Println()

		meanAccuracy += accuracy
		meanPrecision += precision
		meanRecall += recall
		meanFscore += fscore
		meanAUC += auc
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

//---------------
// SPECTF dataset
//---------------

// minimisation parameters for the SPECTF dataset from the paper "Scalable and Secure Logistic Regression via
// Homomorphic Encryption"
func getParametersForSPECTF() (MinimisationParameters, float64, string, string, string, string, float64, float64,
	float64) {
	k := 2
	lambda := 1.0
	step := 0.012
	maxIterations := 450
	// none, standardize or normalize
	preprocessing := "standardize"
	ratio := 0.3

	// initial weights in the paper
	initialWeights := []float64{
		0.921455, -0.377080, -0.313317, 0.796285, 0.992807, -0.650099, 0.865773, 0.484040, 0.021763, 0.809766,
		0.222401, 0.309993, 0.375320, 0.674654, -0.961690, -0.950472, -0.753475, -0.353844, 0.717381, -0.319103,
		-0.664294, -0.573008, -0.401116, 0.216010, -0.810675, 0.961971, -0.412459, -0.507446, 0.585540, -0.273261,
		0.899775, -0.611130, -0.223748, 0.008219, -0.758307, 0.907636, -0.547704, -0.464145, 0.677729, 0.426712,
		-0.862759, 0.090766, -0.421597, -0.429986, 0.410418}

	// floating-point precision when converting from float to int and later back to float
	precisionApproxCoefficients := 1e2
	precisionData := 1e2
	precisionWeights := 1e2

	// data file related parameters
	dataFolder := "../../data/"
	SPECTFTraining := "SPECTF_heart_dataset_training.txt"
	SPECTFTesting := "SPECTF_heart_dataset_testing.txt"
	SPECTFAll := "SPECTF_heart_dataset.txt"
	pathToTraining := dataFolder + SPECTFTraining
	pathToTesting := dataFolder + SPECTFTesting
	pathToAll := dataFolder + SPECTFAll

	return MinimisationParameters{k, lambda, step, maxIterations, initialWeights}, ratio, preprocessing,
		pathToTraining, pathToTesting, pathToAll, precisionApproxCoefficients, precisionData, precisionWeights
}

var SPECTFpaperWeightsWithoutEncryption = []float64{
	0.809215, -0.140885, -0.606209, 0.203335, 0.203389, -0.531782, 0.575154, 0.064924, -0.366572, 0.835623,
	-0.159378, 0.043608, 0.011024, 0.613679, -0.893973, -0.742481, -0.690140, -0.333246, 0.604501, -0.054810,
	-0.624138, -0.443354, -0.540109, 0.172282, -0.722847, 0.703295, -0.626644, -0.508781, 0.092141, -0.585776,
	0.137703, -0.685467, -0.392665, -0.072641, -0.585242, 1.029491, -0.491748, -0.274508, 0.484444, 0.171330,
	-1.250592, -.016082, -0.44540, -0.551420, 0.339719}

var SPECTFpaperWeightsWithEncryption = []float64{
	0.449506, -0.179168, -0.561430, 0.184955, 0.187654, -0.609835, 0.585331, -0.016184, -0.331420, 0.963836,
	0.026561, 0.026819, 0.055403, 0.749877, -0.726896, -0.593111, -0.482201, -0.265006, 0.715793, -0.028347,
	-0.514324, -0.488422, -0.433774, 0.243350, -0.626253, 0.750072, -0.525558, -0.512443, 0.119176, -0.595018,
	0.130557, -0.540884, -0.226714, -0.004119, -0.41977, 1.024436, -0.445246, -0.194982, 0.608593, 0.329321,
	-1.123225, -0.036603, -0.394657, -0.485166, 0.421146}

func TestFindMinimumWeightsForSPECTF(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Find minimum weights for SPECTF")
	fmt.Println("-------------------------------")

	parameters, _, preprocessing, SPECTFTraining, _, _, precisionApproxCoefficients, _, _ := getParametersForSPECTF()
	X, y := encoding.LoadData("SPECTF", SPECTFTraining)

	compareFindMinimumWeights(X, y, parameters, preprocessing, false, precisionApproxCoefficients, SPECTFpaperWeightsWithoutEncryption)
}

func TestFindMinimumWeightsWithEncryptionForSPECTF(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Find minimum weights with encryption for SPECTF")
	fmt.Println("-----------------------------------------------")

	parameters, _, preprocessing, SPECTFTraining, _, _, precisionApproxCoefficients, _, _ := getParametersForSPECTF()
	X, y := encoding.LoadData("SPECTF", SPECTFTraining)

	compareFindMinimumWeights(X, y, parameters, preprocessing, true, precisionApproxCoefficients, SPECTFpaperWeightsWithEncryption)
}

func predictForSPECTF(weights []float64, withEncryption bool) {
	parameters, _, preprocessing, SPECTFTraining, SPECTFTesting, _, precisionApproxCoefficients,
		precisionData, precisionWeights := getParametersForSPECTF()

	Xtrain, ytrain := encoding.LoadData("SPECTF", SPECTFTraining)
	Xtest, ytest := encoding.LoadData("SPECTF", SPECTFTesting)

	accuracy, precision, recall, fscore, auc := predict(Xtrain, ytrain, Xtest, ytest, weights, parameters,
		preprocessing, withEncryption, precisionApproxCoefficients, precisionData, precisionWeights)

	encoding.PrintForLatex(accuracy, precision, recall, fscore, auc)
}

func TestPredictForSPECTF(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for SPECTF")
	fmt.Println("------------------")

	predictForSPECTF(nil, false)
}

func TestPredictForSPECTFRandom(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for SPECTF random")
	fmt.Println("-------------------------")

	parameters, ratio, preprocessing, _, SPECTFAll, _, precisionApproxCoefficients,
		precisionData, precisionWeights := getParametersForSPECTF()

	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("SPECTF", SPECTFAll)

	predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed)
}

func TestPredictWithEncryptionForSPECTF(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict with encryption for SPECTF")
	fmt.Println("----------------------------------")

	predictForSPECTF(nil, true)
}

func TestPredictForSPECTFPaper(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for SPECTF")
	fmt.Println("------------------")

	predictForSPECTF(SPECTFpaperWeightsWithoutEncryption, false)
}

func TestPredictWithEncryptionForSPECTFPaper(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict with encryption for SPECTF")
	fmt.Println("----------------------------------")

	predictForSPECTF(SPECTFpaperWeightsWithEncryption, true)
}

func TestPredictForSPECTFWithGoml(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	parameters, _, SPECTFTraining, SPECTFTesting, _, _, _, _, _ := getParametersForSPECTF()
	Xtrain, ytrain := encoding.LoadData("SPECTF", SPECTFTraining)
	Xtest, ytest := encoding.LoadData("SPECTF", SPECTFTesting)

	model := linear.NewLogistic(base.BatchGA, parameters.step, parameters.lambda, parameters.maxIterations, Xtrain,
		encoding.Int64ToFloat641DArray(ytrain))
	log.LLvl1("theta ", model.Theta())
	for i, v := range parameters.initialWeights {
		parameters.initialWeights[i] = -v
	}
	model.Parameters = parameters.initialWeights

	fmt.Println(model.Learn())

	predictions := make([]int64, len(Xtest))
	predictionsFloat := make([]float64, len(Xtest))
	for i := range Xtest {
		result, _ := model.Predict(Xtest[i], false)
		predictionsFloat[i] = result[0]
		predictions[i] = int64(math.Round(predictionsFloat[i]))
	}

	accuracy := encoding.Accuracy(predictions, ytest)
	precision := encoding.Precision(predictions, ytest)
	recall := encoding.Recall(predictions, ytest)
	fscore := encoding.Fscore(predictions, ytest)
	auc := encoding.AreaUnderCurve(predictionsFloat, ytest)

	fmt.Println("accuracy: ", accuracy)
	fmt.Println("precision:", precision)
	fmt.Println("recall:   ", recall)
	fmt.Println("F-score:  ", fscore)
	fmt.Println("AUC:      ", auc)
	fmt.Println()

	encoding.PrintForLatex(accuracy, precision, recall, fscore, auc)
}

func TestLPredictForSPECTFRandomWtihGoml(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	parameters, _, _, _, path, _, _, _, _ := getParametersForSPECTF()
	X, y := encoding.LoadData("SPECTF", path)
	predictGoml(X, y, 0.3, parameters, 1000, int64(5432109876))
}

//-------------
// Pima dataset
//-------------

// minimisation parameters for the Pima dataset from the paper "Scalable and Secure Logistic Regression via
// Homomorphic Encryption"
func getParametersForPima() (MinimisationParameters, float64, string, string, float64, float64, float64) {
	k := 2
	lambda := 1.0
	step := 0.1
	maxIterations := 200
	preprocessing := "standardize"
	ratio := 0.75

	initialWeights := []float64{
		0.334781, -0.633628, 0.225721, -0.648192, 0.406207, 0.044424, -0.426648, 0.877499, -0.426819}
	//-0.02173989726962445, -0.20274006748091944, 0.5907541058156907, -0.4316412248756341, 0.3245942938035258,	0.06393437349075219, -0.1506383659783502, 0.6900710724439625, -0.013551020637774466}

	// floating-point precision when converting from float to int and later back to float
	precisionApproxCoefficients := 1e2
	precisionData := 1e2
	precisionWeights := 1e2

	// data file related parameters
	dataFolder := "../../data/"
	path := dataFolder + "Pima_dataset.txt"

	return MinimisationParameters{k, lambda, step, maxIterations, initialWeights}, ratio,
		preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights
}

var PimaPaperWeightsWithoutEncryption = []float64{
	-0.802939, 0.354881, 0.932210, -0.192500, 0.051789, -0.103428, 0.613109, 0.337208, 0.141407}

var PimaPaperWeightsWithEncryption = []float64{
	-0.618931, 0.272079, 0.687556, -0.164313, 0.23873, -0.078103, 0.426285, 0.215544, 0.085846}

func TestFindMinimumWeightsForPima(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Find minimum weights for Pima")
	fmt.Println("-----------------------------")

	parameters, _, preprocessing, path, precisionApproxCoefficieents, _, _ := getParametersForPima()
	X, y := encoding.LoadData("Pima", path)
	compareFindMinimumWeights(X, y, parameters, preprocessing, false, precisionApproxCoefficieents, PimaPaperWeightsWithoutEncryption)
}

func TestFindMinimumWeightsWithEncryptionForPima(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Find minimum weights with encryption for PIMA")
	fmt.Println("---------------------------------------------")

	parameters, _, preprocessing, path, precisionApproxCoefficients, _, _ := getParametersForPima()
	X, y := encoding.LoadData("Pima", path)
	compareFindMinimumWeights(X, y, parameters, preprocessing, true, precisionApproxCoefficients, PimaPaperWeightsWithEncryption)
}

func TestPredictForPima(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for Pima")
	fmt.Println("----------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("Pima", path)

	predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed)
}

func TestPredictWithEncryptionForPima(t *testing.T) {
	fmt.Println("Predict with encryption for Pima")
	fmt.Println("--------------------------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("Pima", path)

	predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, true, numberTrials, initSeed)
}

func TestPredictForPimaPaper(t *testing.T) {
	fmt.Println("Predict for Pima")
	fmt.Println("----------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("Pima", path)

	predictWithRandomSplit(X, y, PimaPaperWeightsWithoutEncryption, ratio, parameters, preprocessing,
		precisionApproxCoefficients, precisionData, precisionWeights,
		false, numberTrials, initSeed)
}

func TestPredictForPimaMatlab(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for Pima")
	fmt.Println("----------------")

	//PimaMatlabWeights := []float64{7.7902,	-0.1379,-0.0312, 0.0107,	-0.0023,0.0009,	-0.0797,-0.7906, -0.0141}
	PimaMatlabWeights := []float64{0.8514, -0.4637, -1.0068, 0.1869, -0.0370, 0.1042, -0.6280, -0.2644, -0.1688}

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("Pima", path)

	predictWithRandomSplit(X, y, PimaMatlabWeights, ratio, parameters, preprocessing, precisionApproxCoefficients,
		precisionData, precisionWeights,
		false, numberTrials, initSeed)
}

func TestPredictWithEncryptionForPimaPaper(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict with encryption for Pima")
	fmt.Println("--------------------------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("Pima", path)

	predictWithRandomSplit(X, y, PimaPaperWeightsWithEncryption, ratio, parameters, preprocessing,
		precisionApproxCoefficients, precisionData, precisionWeights,
		true, numberTrials, initSeed)
}

func TestPredictForPimaWithGoml(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	parameters, ratio, _, path, _, _, _ := getParametersForPima()
	X, y := encoding.LoadData("Pima", path)
	predictGoml(X, y, ratio, parameters, 10, int64(5432109876))
}

func getParametersForPCS() (MinimisationParameters, float64, string, string, float64, float64, float64) {
	k := 2
	lambda := 1.0
	step := 0.1
	maxIterations := 25
	preprocessing := "standardize"
	ratio := 0.8

	initialWeights := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}

	// floating-point precision when converting from float to int and later back to float
	precisionApproxCoefficients := 1e0
	precisionData := 1e0
	precisionWeights := 1e0

	// data file related parameters
	dataFolder := "../../data/"
	path := dataFolder + "PCS_dataset.txt"

	return MinimisationParameters{k, lambda, step, maxIterations, initialWeights}, ratio,
		preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights
}

func TestPredictForPCS(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for PCS")
	fmt.Println("---------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPCS()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("PCS", path)

	predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed)
}

func TestPredictForPCSWithGoml(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	parameters, ratio, _, path, _, _, _ := getParametersForPCS()
	X, y := encoding.LoadData("PCS", path)
	predictGoml(X, y, ratio, parameters, 5, int64(5432109876))
}


func getParametersForLBW() (MinimisationParameters, float64, string, string, float64, float64, float64) {
	k := 2
	lambda := 1.0
	step := 0.1
	maxIterations := 25
	preprocessing := "standardize"
	ratio := 0.8

	initialWeights := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}

	// floating-point precision when converting from float to int and later back to float
	precisionApproxCoefficients := 1e0
	precisionData := 1e0
	precisionWeights := 1e0

	// data file related parameters
	dataFolder := "../../data/"
	path := dataFolder + "LBW_dataset.txt"

	return MinimisationParameters{k, lambda, step, maxIterations, initialWeights}, ratio,
		preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights
}

func TestPredictForLBW(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	fmt.Println("Predict for LBW")
	fmt.Println("---------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights := getParametersForLBW()
	numberTrials := 10
	initSeed := int64(5432109876)
	X, y := encoding.LoadData("LBW", path)

	predictWithRandomSplit(X, y,nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights,false, numberTrials, initSeed)
}

func TestPredictForLBWWithGoml(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	parameters, ratio, _, path, _, _, _ := getParametersForLBW()
	X, y := encoding.LoadData("LBW", path)
	predictGoml(X, y, ratio, parameters, 10, int64(5432109876))
}
