package libdrynxencoding_test

import (
	"fmt"
	"github.com/cdipaolo/goml/base"
	"github.com/cdipaolo/goml/linear"
	"github.com/ldsec/drynx/lib/encoding"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/log"
	"math"
	"testing"
)

type preprocessing uint

const (
	PREPROCESSING_NONE preprocessing = iota
	PREPROCESSING_STANDARDIZE
	PREPROCESSING_NORMALIZE
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
	preprocessing preprocessing, withEncryption bool, precisionApproxCoefficients float64, paperWeights []float64) error {

	N := int64(len(Xtrain))
	k := parameters.k
	lambda := parameters.lambda
	step := parameters.step
	maxIterations := parameters.maxIterations
	initialWeights := parameters.initialWeights
	X := libdrynxencoding.Float2DToMatrix(Xtrain)
	libdrynxencoding.Standardise(X)
	X = libdrynxencoding.Augment(X)
	Xtrain = libdrynxencoding.MatrixToFloat2D(X)
	// data providers part + servers part + client part collapsed here for testing

	var weights []float64
	var aggregatedApproxCoefficients [][]float64
	if withEncryption {
		// the clients (public key, private key) pair
		keys := key.NewKeyPair(libunlynx.SuiTe)
		privKey, pubKey := keys.Private, keys.Public
		weights, aggregatedApproxCoefficients = findMinimumWeightsWithEncryption(Xtrain, ytrain, k, maxIterations,
			step, lambda, initialWeights, pubKey, privKey, precisionApproxCoefficients)
	} else {
		weights, aggregatedApproxCoefficients = findMinimumWeights(Xtrain, ytrain, k, maxIterations, step, lambda,
			initialWeights)
	}

	cost := libdrynxencoding.Cost(weights, aggregatedApproxCoefficients, N, lambda)
	logisticCost := libdrynxencoding.LogisticRegressionCost(weights, Xtrain, ytrain, N, lambda)

	log.LLvl2("weights:", weights)
	log.LLvl2("cost:", cost)
	log.LLvl2("logistic cost:", logisticCost)
	log.LLvl2()
	log.LLvl2("Comparison with paper results")
	log.LLvl2("cost:", libdrynxencoding.Cost(paperWeights, aggregatedApproxCoefficients, N, lambda))
	log.LLvl2("logistic cost:", libdrynxencoding.LogisticRegressionCost(paperWeights, Xtrain, ytrain, N, lambda))
	log.LLvl2()

	return nil
}

func findMinimumWeights(X [][]float64, y []int64, k int, maxIterations int, step float64, lambda float64, initialWeights []float64) ([]float64, [][]float64) {

	// each data provider computes its approximation coefficients on its side and then sends them to its chosen server
	N := len(X)
	approxCoefficients := make([][][]float64, N)
	for i := range X {
		approxCoefficients[i] = libdrynxencoding.ComputeAllApproxCoefficients(X[i], y[i], k)
	}
	aggregatedApproxCoefficients := libdrynxencoding.AggregateApproxCoefficients(approxCoefficients)

	// the client computes the weights on its side
	weights := libdrynxencoding.FindMinimumWeights(aggregatedApproxCoefficients,
		initialWeights, int64(N),
		lambda, step, maxIterations)

	log.Lvl2("weights 1", weights)
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
		approxCoefficients[i] = libdrynxencoding.Float64ToInt642DArrayWithPrecision(
			libdrynxencoding.ComputeAllApproxCoefficients(X[i], y[i], k),
			precisionApproxCoefficients)

		encryptedApproxCoefficients[i], _ = libdrynxencoding.ComputeEncryptedApproxCoefficients(approxCoefficients[i], pubKey)
	}

	encryptedAggregatedApproxCoefficients := libdrynxencoding.AggregateEncryptedApproxCoefficients(encryptedApproxCoefficients)

	weights, aggregatedApproxCoefficients := libdrynxencoding.FindMinimumWeightsWithEncryption(
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
	preprocessing preprocessing, withEncryption bool,
	precisionApproxCoefficients float64, precisionData float64, precisionWeights float64) (float64,
	float64, float64, float64, float64, error) {

	k := parameters.k
	lambda := parameters.lambda
	step := parameters.step
	maxIterations := parameters.maxIterations
	initialWeights := parameters.initialWeights

	log.Lvl2("init:", initialWeights)

	// save the original training set in order to standardise the testing set
	XtrainSaved := libdrynxencoding.Float2DToMatrix(Xtrain)

	// data pre-processing
	matrixXTrain := libdrynxencoding.Float2DToMatrix(Xtrain)
	libdrynxencoding.Standardise(matrixXTrain)
	matrixXTrain = libdrynxencoding.Augment(matrixXTrain)
	Xtrain = libdrynxencoding.MatrixToFloat2D(matrixXTrain)

	// the client's (public key, private key) pair
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public

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
	log.Lvl2("weights:", weights)
	//log.Lvl2("approx:", approxCoefficients)

	// prediction computation
	// standardise the testing set using the mean and standard deviation of the training set
	matrixXTest := libdrynxencoding.Float2DToMatrix(Xtest)
	if preprocessing == PREPROCESSING_STANDARDIZE {
		libdrynxencoding.StandardiseWithTrain(matrixXTest, XtrainSaved)
	} else if preprocessing == PREPROCESSING_NORMALIZE {
		libdrynxencoding.NormalizeWith(matrixXTest, XtrainSaved)
	}
	Xtest = libdrynxencoding.MatrixToFloat2D(matrixXTest)
	// note: the test data does not need to be augmented with 1s

	predictions := make([]int64, len(Xtest))
	predictionsFloat := make([]float64, len(Xtest))
	if withEncryption {
		for i := range Xtest {
			encryptedData := libunlynx.EncryptIntVector(pubKey,
				libdrynxencoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData))

			predictionsFloat[i] = libdrynxencoding.PredictHomomorphic(*encryptedData,
				weights,
				privKey,
				precisionWeights, precisionData)

			predictions[i] = int64(math.Round(predictionsFloat[i])) //todo: define threshold parameter

			predict := libdrynxencoding.Predict(*libunlynx.EncryptIntVector(pubKey,
				libdrynxencoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData)),
				weights,
				privKey,
				precisionWeights, precisionData)

			predictHomomorphic := libdrynxencoding.PredictHomomorphic(
				*libunlynx.EncryptIntVector(pubKey,
					libdrynxencoding.Float64ToInt641DArrayWithPrecision(Xtest[i], precisionData)),
				weights,
				privKey,
				precisionWeights, precisionData)

			predictClear := libdrynxencoding.PredictInClear(Xtest[i], weights)

			fmt.Printf("%12.8e %12.8e %12.8e %1d %2d\n", predictClear, predict, predictHomomorphic, predictions[i],
				yTest[i])
		}
	} else {
		for i := range Xtest {
			predictionsFloat[i] = libdrynxencoding.PredictInClear(Xtest[i], weights)
			predictions[i] = int64(math.Round(predictionsFloat[i]))
			fmt.Printf("%12.8e %1d %2d\n", libdrynxencoding.PredictInClear(Xtest[i], weights), predictions[i], yTest[i])
		}
	}

	accuracy := libdrynxencoding.Accuracy(predictions, yTest)
	precision := libdrynxencoding.Precision(predictions, yTest)
	recall := libdrynxencoding.Recall(predictions, yTest)
	fscore := libdrynxencoding.Fscore(predictions, yTest)
	auc := libdrynxencoding.AreaUnderCurve(predictionsFloat, yTest)

	log.Lvl2("accuracy: ", accuracy)
	log.Lvl2("precision:", precision)
	log.Lvl2("recall:   ", recall)
	log.Lvl2("F-score:  ", fscore)
	log.Lvl2("AUC:      ", auc)
	log.Lvl2()

	// compute the TPR (True Positive Rate) and FPR (False Positive Rate)
	//tpr, fpr := encoding.ComputeTPRFPR(predictionsFloat, yTest)
	// save to file (for plotting the ROC)
	//encoding.SaveToFile(tpr, "../../data/tpr.txt")
	//encoding.SaveToFile(fpr, "../../data/fpr.txt")

	return accuracy, precision, recall, fscore, auc, nil
}

func predictWithRandomSplit(X [][]float64, y []int64, weights []float64,
	ratio float64, parameters MinimisationParameters, preprocessing preprocessing, precisionApproxCoefficients float64,
	precisionData float64, precisionWeights float64, withEncryption bool, numberTrials int, initSeed int64) error {

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
		Xtrain, ytrain, Xtest, ytest := libdrynxencoding.PartitionDataset(X, y, ratio, true, seed)

		log.Lvl2("training set:", len(Xtrain))
		log.Lvl2("testing set: ", len(Xtest))

		var err error
		accuracy[i], precision[i], recall[i], fscore[i], auc[i], err = predict(Xtrain, ytrain, Xtest, ytest, weights,
			parameters, preprocessing, withEncryption, precisionApproxCoefficients, precisionData, precisionWeights)
		if err != nil {
			return err
		}

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

	log.Lvl2("Final evaluation over", numberTrials, "trials")
	log.Lvl2("accuracy: ", meanAccuracy)
	log.Lvl2("precision:", meanPrecision)
	log.Lvl2("recall:   ", meanRecall)
	log.Lvl2("F-score:  ", meanFscore)
	log.Lvl2("AUC:      ", meanAUC)
	log.Lvl2()

	libdrynxencoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)

	return nil
}

func predictGoml(X [][]float64, y []int64, ratio float64, parameters MinimisationParameters, numberTrials int, initSeed int64) {

	meanAccuracy := 0.0
	meanPrecision := 0.0
	meanRecall := 0.0
	meanFscore := 0.0
	meanAUC := 0.0

	for i := 0; i < numberTrials; i++ {

		seed := initSeed + int64(i)
		Xtrain, ytrain, Xtest, ytest := libdrynxencoding.PartitionDataset(X, y, ratio, true, seed)

		model := linear.NewLogistic(base.BatchGA, parameters.step, parameters.lambda, parameters.maxIterations, Xtrain, libdrynxencoding.Int64ToFloat641DArray(ytrain))

		log.Lvl2(model.Learn())

		predictions := make([]int64, len(Xtest))
		predictionsFloat := make([]float64, len(Xtest))
		for i := range Xtest {
			result, _ := model.Predict(Xtest[i], false)

			predictionsFloat[i] = result[0]
			predictions[i] = int64(math.Round(predictionsFloat[i]))
		}

		accuracy := libdrynxencoding.Accuracy(predictions, ytest)
		precision := libdrynxencoding.Precision(predictions, ytest)
		recall := libdrynxencoding.Recall(predictions, ytest)
		fscore := libdrynxencoding.Fscore(predictions, ytest)
		auc := libdrynxencoding.AreaUnderCurve(predictionsFloat, ytest)

		log.Lvl2("accuracy: ", accuracy)
		log.Lvl2("precision:", precision)
		log.Lvl2("recall:   ", recall)
		log.Lvl2("F-score:  ", fscore)
		log.Lvl2("AUC:      ", auc)
		log.Lvl2()

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

	log.Lvl2("Final evaluation over", numberTrials, "trials")
	log.Lvl2("accuracy: ", meanAccuracy)
	log.Lvl2("precision:", meanPrecision)
	log.Lvl2("recall:   ", meanRecall)
	log.Lvl2("F-score:  ", meanFscore)
	log.Lvl2("AUC:      ", meanAUC)
	log.Lvl2()

	libdrynxencoding.PrintForLatex(meanAccuracy, meanPrecision, meanRecall, meanFscore, meanAUC)
}

//---------------
// SPECTF dataset
//---------------

// minimisation parameters for the SPECTF dataset from the paper "Scalable and Secure Logistic Regression via
// Homomorphic Encryption"
func getParametersForSPECTF() (MinimisationParameters, float64, preprocessing, string, string, string, float64, float64,
	float64) {
	k := 2
	lambda := 1.0
	step := 0.012
	maxIterations := 450
	// none, standardize or normalize
	preprocessing := PREPROCESSING_STANDARDIZE
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
	log.Lvl2("Find minimum weights for SPECTF")
	log.Lvl2("-------------------------------")

	parameters, _, preprocessing, SPECTFTraining, _, _, precisionApproxCoefficients, _, _ := getParametersForSPECTF()
	matrix, vector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTraining)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, compareFindMinimumWeights(X, y, parameters, preprocessing, false, precisionApproxCoefficients, SPECTFpaperWeightsWithoutEncryption))
}

func TestFindMinimumWeightsWithEncryptionForSPECTF(t *testing.T) {
	log.Lvl2("Find minimum weights with encryption for SPECTF")
	log.Lvl2("-----------------------------------------------")

	parameters, _, preprocessing, SPECTFTraining, _, _, precisionApproxCoefficients, _, _ := getParametersForSPECTF()
	matrix, vector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTraining)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, compareFindMinimumWeights(X, y, parameters, preprocessing, true, precisionApproxCoefficients, SPECTFpaperWeightsWithEncryption))
}

func predictForSPECTF(weights []float64, withEncryption bool) error {
	parameters, _, preprocessing, SPECTFTraining, SPECTFTesting, _, precisionApproxCoefficients,
		precisionData, precisionWeights := getParametersForSPECTF()

	trainMatrix, trainVector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTraining)
	if err != nil {
		return err
	}
	testMatrix, testVector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTesting)
	if err != nil {
		return err
	}

	Xtrain, ytrain := libdrynxencoding.MatrixToFloat2D(trainMatrix), libdrynxencoding.VectorToInt(trainVector)
	Xtest, ytest := libdrynxencoding.MatrixToFloat2D(testMatrix), libdrynxencoding.VectorToInt(testVector)

	accuracy, precision, recall, fscore, auc, err := predict(Xtrain, ytrain, Xtest, ytest, weights, parameters,
		preprocessing, withEncryption, precisionApproxCoefficients, precisionData, precisionWeights)

	libdrynxencoding.PrintForLatex(accuracy, precision, recall, fscore, auc)

	return nil
}

func TestPredictForSPECTF(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for SPECTF")
	log.Lvl2("------------------")

	require.NoError(t, predictForSPECTF(nil, false))
}

func TestPredictForSPECTFRandom(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for SPECTF random")
	log.Lvl2("-------------------------")

	parameters, ratio, preprocessing, _, SPECTFAll, _, precisionApproxCoefficients,
		precisionData, precisionWeights := getParametersForSPECTF()

	numberTrials := 1 //10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("SPECTF", SPECTFAll)
	require.NoError(t, err)
	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed))
}

func TestPredictWithEncryptionForSPECTF(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict with encryption for SPECTF")
	log.Lvl2("----------------------------------")

	require.NoError(t, predictForSPECTF(nil, true))
}

func TestPredictForSPECTFPaper(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for SPECTF")
	log.Lvl2("------------------")

	require.NoError(t, predictForSPECTF(SPECTFpaperWeightsWithoutEncryption, false))
}

func TestPredictWithEncryptionForSPECTFPaper(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict with encryption for SPECTF")
	log.Lvl2("----------------------------------")

	require.NoError(t, predictForSPECTF(SPECTFpaperWeightsWithEncryption, true))
}

func TestPredictForSPECTFWithGoml(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	parameters, _, _, SPECTFTraining, SPECTFTesting, _, _, _, _ := getParametersForSPECTF()
	trainMatrix, trainVector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTraining)
	require.NoError(t, err)
	testMatrix, testVector, err := libdrynxencoding.LoadData("SPECTF", SPECTFTesting)
	require.NoError(t, err)

	Xtrain, ytrain := libdrynxencoding.MatrixToFloat2D(trainMatrix), libdrynxencoding.VectorToInt(trainVector)
	Xtest, ytest := libdrynxencoding.MatrixToFloat2D(testMatrix), libdrynxencoding.VectorToInt(testVector)

	model := linear.NewLogistic(base.BatchGA, parameters.step, parameters.lambda, parameters.maxIterations, Xtrain,
		libdrynxencoding.Int64ToFloat641DArray(ytrain))
	for i, v := range parameters.initialWeights {
		parameters.initialWeights[i] = -v
	}
	model.Parameters = parameters.initialWeights

	log.Lvl2(model.Learn())

	predictions := make([]int64, len(Xtest))
	predictionsFloat := make([]float64, len(Xtest))
	for i := range Xtest {
		result, _ := model.Predict(Xtest[i], false)
		predictionsFloat[i] = result[0]
		predictions[i] = int64(math.Round(predictionsFloat[i]))
	}

	accuracy := libdrynxencoding.Accuracy(predictions, ytest)
	precision := libdrynxencoding.Precision(predictions, ytest)
	recall := libdrynxencoding.Recall(predictions, ytest)
	fscore := libdrynxencoding.Fscore(predictions, ytest)
	auc := libdrynxencoding.AreaUnderCurve(predictionsFloat, ytest)

	log.Lvl2("accuracy: ", accuracy)
	log.Lvl2("precision:", precision)
	log.Lvl2("recall:   ", recall)
	log.Lvl2("F-score:  ", fscore)
	log.Lvl2("AUC:      ", auc)
	log.Lvl2()

	libdrynxencoding.PrintForLatex(accuracy, precision, recall, fscore, auc)
}

func TestLPredictForSPECTFRandomWtihGoml(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	parameters, _, _, _, path, _, _, _, _ := getParametersForSPECTF()
	matrix, vector, err := libdrynxencoding.LoadData("SPECTF", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	predictGoml(X, y, 0.3, parameters, 1000, int64(5432109876))
}

//-------------
// Pima dataset
//-------------

// minimisation parameters for the Pima dataset from the paper "Scalable and Secure Logistic Regression via
// Homomorphic Encryption"
func getParametersForPima() (MinimisationParameters, float64, preprocessing, string, float64, float64, float64) {
	k := 2
	lambda := 1.0
	step := 0.1
	maxIterations := 200
	preprocessing := PREPROCESSING_STANDARDIZE
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
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Find minimum weights for Pima")
	log.Lvl2("-----------------------------")

	parameters, _, preprocessing, path, precisionApproxCoefficieents, _, _ := getParametersForPima()
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)
	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)
	require.NoError(t, compareFindMinimumWeights(X, y, parameters, preprocessing, false, precisionApproxCoefficieents, PimaPaperWeightsWithoutEncryption))
}

func TestFindMinimumWeightsWithEncryptionForPima(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Find minimum weights with encryption for PIMA")
	log.Lvl2("---------------------------------------------")

	parameters, _, preprocessing, path, precisionApproxCoefficients, _, _ := getParametersForPima()
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)
	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)
	require.NoError(t, compareFindMinimumWeights(X, y, parameters, preprocessing, true, precisionApproxCoefficients, PimaPaperWeightsWithEncryption))
}

func TestPredictForPima(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for Pima")
	log.Lvl2("----------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed))
}

func TestPredictWithEncryptionForPima(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict with encryption for Pima")
	log.Lvl2("--------------------------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, true, numberTrials, initSeed))
}

func TestPredictForPimaPaper(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for Pima")
	log.Lvl2("----------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, PimaPaperWeightsWithoutEncryption, ratio, parameters, preprocessing,
		precisionApproxCoefficients, precisionData, precisionWeights,
		false, numberTrials, initSeed))
}

func TestPredictForPimaMatlab(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for Pima")
	log.Lvl2("----------------")

	//PimaMatlabWeights := []float64{7.7902,	-0.1379,-0.0312, 0.0107,	-0.0023,0.0009,	-0.0797,-0.7906, -0.0141}
	PimaMatlabWeights := []float64{0.8514, -0.4637, -1.0068, 0.1869, -0.0370, 0.1042, -0.6280, -0.2644, -0.1688}

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, PimaMatlabWeights, ratio, parameters, preprocessing, precisionApproxCoefficients,
		precisionData, precisionWeights,
		false, numberTrials, initSeed))
}

func TestPredictWithEncryptionForPimaPaper(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict with encryption for Pima")
	log.Lvl2("--------------------------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights := getParametersForPima()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, PimaPaperWeightsWithEncryption, ratio, parameters, preprocessing,
		precisionApproxCoefficients, precisionData, precisionWeights,
		true, numberTrials, initSeed))
}

func TestPredictForPimaWithGoml(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	parameters, ratio, _, path, _, _, _ := getParametersForPima()
	matrix, vector, err := libdrynxencoding.LoadData("Pima", path)
	require.NoError(t, err)

	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	predictGoml(X, y, ratio, parameters, 10, int64(5432109876))
}

func getParametersForPCS() (MinimisationParameters, float64, preprocessing, string, float64, float64, float64) {
	k := 2
	lambda := 1.0
	step := 0.1
	maxIterations := 25
	preprocessing := PREPROCESSING_STANDARDIZE
	ratio := 0.8

	initialWeights := []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0}

	// floating-point precision when converting from float to int and later back to float
	precisionApproxCoefficients := 1e0
	precisionData := 1e0
	precisionWeights := 1e0

	// data file related parameters
	dataFolder := "../../data/"
	path := dataFolder + "PCS_dataset_testing.txt"

	return MinimisationParameters{k, lambda, step, maxIterations, initialWeights}, ratio,
		preprocessing, path, precisionApproxCoefficients, precisionData, precisionWeights
}

func TestPredictForPCS(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	log.Lvl2("Predict for PCS")
	log.Lvl2("---------------")

	parameters, ratio, preprocessing, path, precisionApproxCoefficients, precisionData,
		precisionWeights := getParametersForPCS()
	numberTrials := 10
	initSeed := int64(5432109876)
	matrix, vector, err := libdrynxencoding.LoadData("PCS", path)
	require.NoError(t, err)
	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)

	require.NoError(t, predictWithRandomSplit(X, y, nil, ratio, parameters, preprocessing, precisionApproxCoefficients, precisionData,
		precisionWeights, false, numberTrials, initSeed))
}

func TestPredictForPCSWithGoml(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	parameters, ratio, _, path, _, _, _ := getParametersForPCS()
	matrix, vector, err := libdrynxencoding.LoadData("PCS", path)
	require.NoError(t, err)
	X, y := libdrynxencoding.MatrixToFloat2D(matrix), libdrynxencoding.VectorToInt(vector)
	predictGoml(X, y, ratio, parameters, 5, int64(5432109876))
}
