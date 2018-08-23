package encoding_test

import (
	"github.com/cdipaolo/goml/base"
	"github.com/cdipaolo/goml/linear"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"gonum.org/v1/gonum/stat/combin"

	"fmt"
	"math"
	"testing"

	"github.com/dedis/onet/log"
	"github.com/dedis/kyber"
	"github.com/lca1/drynx/lib"
	"github.com/dedis/kyber/pairing/bn256"
)

func TestComputeApproxCoefficients(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := []float64{0, 1, 2, 3, 4}
	y := int64(1)
	k := 1
	expected := [][]float64{{0, 1, 2, 3, 4}}
	actual := encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 1
	expected = [][]float64{{0, -1, -2, -3, -4}}
	actual = encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(1)
	k = 2
	expected = [][]float64{
		{0, 1, 2, 3, 4},
		{0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16}}
	actual = encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 2
	expected = [][]float64{
		{0, -1, -2, -3, -4},
		{0, 0, 0, 0, 0, 1, 2, 3, 4, 4, 6, 8, 9, 12, 16}}
	actual = encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(1)
	k = 3
	expected = [][]float64{
		{0, 1, 2, 3, 4},
		{0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16, -8, -12, -16, -18, -24, -32, -27, -36, -48, -64}}
	actual = encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 3
	expected = [][]float64{
		{0, -1, -2, -3, -4},
		{0, 0, 0, 0, 0, 1, 2, 3, 4, 4, 6, 8, 9, 12, 16},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16, -8, -12, -16, -18, -24, -32, -27, -36, -48, -64}}
	actual = encoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)
}

func TestComputeEncryptedApproxCoefficients(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := []float64{0, 1, 2, 3, 4}
	y := int64(1)
	k := 1

	privKey, pubKey := libunlynx.GenKey()

	expected := make([][]int64, k)
	actual := make([][]int64, k)

	approxCoeffs := encoding.Float64ToInt642DArray(encoding.ComputeDistinctApproxCoefficients(X, y, k))
	encryptedApproxCoeffs, _ := encoding.ComputeEncryptedApproxCoefficients(approxCoeffs, pubKey)

	for j := 0; j < k; j++ {
		expected[j] = approxCoeffs[j]
		actual[j] = libunlynx.DecryptIntVector(privKey, libunlynx.EncryptIntVector(pubKey, approxCoeffs[j]))
	}

	assert.Equal(t, expected, actual)

	X = []float64{0, -1, -2, -3, -4}
	y = int64(0)
	k = 1

	approxCoeffs = encoding.Float64ToInt642DArray(encoding.ComputeDistinctApproxCoefficients(X, y, k))
	encryptedApproxCoeffs, _ = encoding.ComputeEncryptedApproxCoefficients(approxCoeffs, pubKey)

	for j := 0; j < k; j++ {
		expected[j] = libunlynx.DecryptIntVector(privKey, encryptedApproxCoeffs[j])
		actual[j] = libunlynx.DecryptIntVector(privKey, libunlynx.EncryptIntVector(pubKey, approxCoeffs[j]))
	}
	log.LLvl1(actual)

	assert.Equal(t, expected, actual)
}

func TestCombinationsWithRepetitionEfficient(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	//tests correctness and efficiency
	//int64 : -9223372036854775808 to 9223372036854775807

	n := int64(0)
	k := int64(0)
	expected := int64(1)
	actual := encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(4)
	expected = int64(1)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(-1)
	expected = int64(1)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(-1)
	k = int64(3)
	expected = int64(1)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(1)
	expected = int64(3)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(5)
	k = int64(3)
	expected = int64(35)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(60)
	k = int64(10)
	expected = int64(340032449328)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(80)
	k = int64(10)
	expected = int64(5085018206136)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(100)
	k = int64(10)
	expected = int64(42634215112710)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(200)
	k = int64(10)
	expected = int64(35216131179263320)
	actual = encoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	//possibly overflows int64 during the computation
	//n = int64(300)
	//k = int64(10)
	//expected = int64(1887629299319420580)
	//actual = encoding.CombinationsWithRepetition(n, k)
	//assert.Equal(t, expected, actual)
}

func TestAggregateEncryptedApproxCoefficients(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	// data providers data
	X := [][]float64{{0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}}
	y := []int64{1, 1}
	k := 1
	N := len(X)

	privKey, pubKey := libunlynx.GenKey()

	approxCoefficients := make([][][]float64, N)
	encryptedApproxCoefficients := make([][]*libunlynx.CipherVector, N)

	// compute the approximation coefficients and encrypt them
	for i := 0; i < N; i++ {
		approxCoefficients[i] = encoding.ComputeAllApproxCoefficients(X[i], y[i], k)
		encryptedApproxCoefficients[i], _ = encoding.ComputeEncryptedApproxCoefficients(encoding.
			Float64ToInt642DArray(approxCoefficients[i]), pubKey)
	}

	// aggregate the encrypted approximation coefficients
	actual := encoding.AggregateEncryptedApproxCoefficients(encryptedApproxCoefficients)
	// aggregate the approximation coefficients
	expected := encoding.Float64ToInt642DArray(encoding.AggregateApproxCoefficients(approxCoefficients))

	// compare the decrypted aggregated approximation coefficients
	for j := 0; j < k; j++ {
		assert.Equal(t, expected[j], libunlynx.DecryptIntVector(privKey, actual[j]))
	}
}

func TestPredictWithInt(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	// integer weights
	X := []float64{0, 1, 2, 3, 4}
	privKey, pubKey := libunlynx.GenKey()
	encryptedData := libunlynx.EncryptIntVector(pubKey, encoding.Float64ToInt641DArray(X))
	precision := 1e1

	weights := []float64{1, 2, 3, 4, 5, 6}
	actual := encoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected := encoding.PredictInClear(X, weights)
	assert.Equal(t, expected, actual)
}

func TestPredictWithFloat(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := []float64{0, 1, 2, 3, 4}
	privKey, pubKey := libunlynx.GenKey()
	encryptedData := libunlynx.EncryptIntVector(pubKey, encoding.Float64ToInt641DArray(X))
	precision := 1e1

	// used to defined the maximal error allowed (?)
	ratio := 0.01

	// float weights
	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6}
	actual := encoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected := encoding.PredictInClear(X, weights)
	epsilon := expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{0.5, 0.5, 0.5, 0.5, 0.5, 0.5}
	actual = encoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{1.2, 2.4, 3.4, 4.6, 4.5, 1.4}
	actual = encoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{-1.2, -2.4, -3.4, 4.6, 4.5, 1.4}
	actual = encoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)
}

func TestPredictWithIntHomomorphic(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	// integer weights
	X := []float64{0, 1, 2, 3, 4}
	privKey, pubKey := libunlynx.GenKey()
	encryptedData := libunlynx.EncryptIntVector(pubKey, encoding.Float64ToInt641DArray(X))

	weights := []float64{1, 2, 3, 4, 5, 6}
	actual := encoding.PredictHomomorphic(*encryptedData, weights, privKey, 1, 1)
	expected := encoding.PredictInClear(X, weights)
	assert.Equal(t, expected, actual)
	showDetails(expected, actual, 0)
}

func TestPredictWithFloatHomomorphic(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := []float64{1, 2, 6, 5, 5}
	privKey, pubKey := libunlynx.GenKey()
	encryptedData := libunlynx.EncryptIntVector(pubKey, encoding.Float64ToInt641DArray(X))

	// used to defined the maximal error allowed (?)
	ratio := 0.01

	// float weights
	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6}
	actual := encoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e1, 1e0)
	expected := encoding.PredictInClear(X, weights)
	epsilon := expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{0.1111, 0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = encoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e3, 1e0)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{0.1111, 0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = encoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e4, 1e0)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{-0.1111, -0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = encoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e4, 1e0)
	expected = encoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)
}

func showDetails(expected float64, actual float64, epsilon float64) {
	fmt.Println("expected:", expected)
	fmt.Println("actual:  ", actual)
	fmt.Println("epsilon: ", epsilon)
	fmt.Println("effective difference:", math.Abs(actual-expected))
}

func TestInt64ToFloat641DArray(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	arrayInt64 := []int64{0, 1, 2, 3, 4}
	expected := []float64{0.0, 1.0, 2.0, 3.0, 4.0}
	actual := encoding.Int64ToFloat641DArray(arrayInt64)
	assert.Equal(t, expected, actual)
}

func TestInt64ToFloat642DArray(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	arrayInt64 := [][]int64{{0, 1, 2, 3, 4}, {5, 6, 7, 8, 9}}
	expected := [][]float64{{0.0, 1.0, 2.0, 3.0, 4.0}, {5.0, 6.0, 7.0, 8.0, 9.0}}
	actual := encoding.Int64ToFloat642DArray(arrayInt64)
	assert.Equal(t, expected, actual)
}

func TestGradient(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{{1, 2, 3, 4, 5}}
	y := []int64{1}
	k := 1
	N := len(X) //len(X[0]) * 10
	N_64 := int64(N)

	lambda := 10.0
	step := 0.0001
	maxIterations := 100000

	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	approxCoeffs := encoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	// gradient for k = 1
	expected := make([]float64, len(weights))
	for i := 0; i < len(weights); i++ {
		expected[i] = (1 / float64(N)) * encoding.PolyApproxCoefficients[k] * float64(approxCoeffs[k-1][i])
		if i >= 0 {
			expected[i] += (lambda / float64(N)) * weights[i]
		}
	}
	actual := encoding.Gradient(weights, approxCoeffs, k, N_64, lambda)
	assert.Equal(t, expected, actual)

	// gradient for k = 2
	k = 2
	approxCoeffs = encoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	expected = encoding.GradientFor2(weights, approxCoeffs, k, N, lambda)
	actual = encoding.Gradient(weights, approxCoeffs, k, N_64, lambda)
	assert.Equal(t, expected, actual)

	testX := make([][]float64, 1)
	testX[0] = X[0][1:]
	testY := []float64{float64(y[0])}
	model := linear.NewLogistic(base.BatchGA, step, lambda, maxIterations, testX, testY)
	fmt.Println(model.Learn())
	for j := 0; j < len(weights); j++ {
		fmt.Println(model.Dj(j))
	}
}

func TestCost(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{{1, 0, 1, 2, 3, 4}}
	y := []int64{1}
	k := 1
	N := len(X)
	N_64 := int64(N)

	lambda := 1.0

	approxCoeffs := encoding.ComputeAllApproxCoefficients(X[0], y[0], k)
	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := encoding.AggregateApproxCoefficients(allApproxCoeffs)

	weights := []float64{0, 1, 2, 3, 4, 5}

	expectedCost := 0.0
	for i := 0; i < len(weights); i++ {
		expectedCost += weights[i] * float64(aggregatedApproxCoeffs[0][i])
	}
	expectedCost *= (1 / float64(N)) * encoding.PolyApproxCoefficients[k]
	expectedCost -= encoding.PolyApproxCoefficients[0]

	// l2-regularizer contribution
	for i := 0; i < len(weights); i++ {
		expectedCost += weights[i] * weights[i] * (lambda / 2 * float64(N))
	}

	actuaCost := encoding.Cost(weights, aggregatedApproxCoeffs, N_64, lambda)

	assert.Equal(t, expectedCost, actuaCost)
}

func TestLogisticCost(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{{1.0, 0.0, 1.0, 2.0, 3.0, 4.0}}
	y := []int64{1}
	N := int64(1)

	lambda := 1.0

	weights := []float64{0.035, 0.00000, 0.03712, 0.07425, 0.11137, 0.14849}
	expected := 0.29668003759705
	actual := encoding.LogisticRegressionCost(weights, X, y, N, lambda)
	assert.Equal(t, expected, actual)
}

func TestFindMinimumWeightsDegreeOne(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{{1, 0, 1, 2, 3, 4}}
	y := []int64{1}
	k := 1
	N := int64(len(X))
	d := len(X[0]) - 1

	lambda := 10.0
	step := 0.0001
	maxIterations := 100000

	initialWeights := make([]float64, d+1)
	for i := 0; i < len(initialWeights); i++ {
		initialWeights[i] = 0.1
	}

	approxCoeffs := encoding.ComputeAllApproxCoefficients(X[0], y[0], k)
	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := encoding.AggregateApproxCoefficients(allApproxCoeffs)

	expectedWeights := encoding.ComputeMinimumWeights(aggregatedApproxCoeffs, lambda)
	actualWeights := encoding.FindMinimumWeights(aggregatedApproxCoeffs, initialWeights, N, lambda, step,
		maxIterations)

	// cheating
	epsilon := 0.0001
	maxEpsilon := 0.0
	for i := 0; i < len(actualWeights); i++ {
		assert.Equal(t, true, math.Abs(actualWeights[i]-expectedWeights[i]) < epsilon)
		if actualWeights[i]-expectedWeights[i] > maxEpsilon {
			maxEpsilon = actualWeights[i] - expectedWeights[i]
		}
	}
	//assert.Equal(t, expectedWeights, actualWeights)

	fmt.Println("expected weights:", expectedWeights)
	fmt.Println("actual weights:", actualWeights)
	fmt.Println("max effective epsilon:", maxEpsilon)

	costActualWeights := encoding.Cost(actualWeights, aggregatedApproxCoeffs, N, lambda)
	costExpectedWeights := encoding.Cost(expectedWeights, aggregatedApproxCoeffs, N, lambda)
	fmt.Println("cost expected weights:", costExpectedWeights)
	fmt.Println("cost actual weights:", costActualWeights)

	testX := make([][]float64, 1)
	testX[0] = X[0][1:]
	testY := []float64{float64(y[0])}
	model := linear.NewLogistic(base.BatchGA, step, lambda, maxIterations, testX, testY)
	fmt.Println(model.Learn())
}

func TestFindMinimumWeights(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{{1, 0, 1, 2, 3, 4}}
	y := []int64{1}
	k := 2
	N := int64(len(X))

	lambda := 1.0
	step := 0.001
	maxIterations := 100000

	initialWeights := make([]float64, len(X[0]))
	for i := 0; i < len(initialWeights); i++ {
		initialWeights[i] = 0.2
	}

	approxCoeffs := encoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := encoding.AggregateApproxCoefficients(allApproxCoeffs)

	weights := encoding.FindMinimumWeights(aggregatedApproxCoeffs, initialWeights, N, lambda, step, maxIterations)
	cost := encoding.Cost(weights, aggregatedApproxCoeffs, N, lambda)
	logisticCost := encoding.LogisticRegressionCost(weights, X, y, N, lambda)

	log.LLvl1(aggregatedApproxCoeffs)
	fmt.Println("approx. coeffs.:", approxCoeffs)
	fmt.Println("weights:", weights)
	fmt.Println("cost:", cost)
	fmt.Println("logistic cost:", logisticCost)
	fmt.Println()

	testX := make([][]float64, 1)
	testX[0] = X[0][1:]
	testY := []float64{float64(y[0])}
	model := linear.NewLogistic(base.BatchGA, step, lambda, maxIterations, testX, testY)

	fmt.Println(model.Learn())
	weightsPackage := []float64{0.035, 0.00000, 0.03712, 0.07425, 0.11137, 0.14849}
	fmt.Println("cost:", encoding.Cost(weightsPackage, approxCoeffs, N, lambda))
	fmt.Println("logistic cost:", encoding.LogisticRegressionCost(weightsPackage, X, y, N, lambda))
}

func TestRange(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	expected := []int64{0, 1, 2, 3, 4, 5}
	actual := encoding.Range(0, 6)
	assert.Equal(t, expected, actual)

	expected = []int64{10, 11, 12, 13}
	actual = encoding.Range(10, 14)
	assert.Equal(t, expected, actual)
}

func TestCombinations(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	result := combin.Cartesian(nil, [][]float64{{1, 2, 3}, {1, 2, 3}, {1, 2, 3}})
	fmt.Println(result)
}

func TestCartesianProduct(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	start := int64(0)
	end := int64(2)
	dim := 3
	actual := encoding.CartesianProduct(start, end, dim)
	expected := [][]int64{{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1}, {1, 0, 0}, {1, 0, 1}, {1, 1, 0}, {1, 1, 1}}
	assert.Equal(t, expected, actual)

	start = int64(0)
	end = int64(3)
	dim = 2
	actual = encoding.CartesianProduct(start, end, dim)
	expected = [][]int64{{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}, {1, 2}, {2, 0}, {2, 1}, {2, 2}}
	assert.Equal(t, expected, actual)
}

func TestAddSub(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	privKey, pubKey := libunlynx.GenKey()

	ct := libunlynx.NewCipherText()

	m := int64(-6)
	otherCt := libunlynx.EncryptInt(pubKey, m)

	ct.Add(*ct, *otherCt)
	pt := libunlynx.DecryptIntWithNeg(privKey, *ct)

	assert.Equal(t, pt, m)
}

func TestEncodeDecodeLogisticRegression(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	// data
	data := [][]float64{{0, 1.3, 5.0, 3.4, 3.2},
		{1, 2.0, 4.4, 4.2, 3.3},
		{1, 1.2, 1.9, 3.8, 2.3},
		{0, 1.0, 4.5, 2.2, 3.8},
		{1, 1.7, 2.8, 3.8, 2.7}}

	labelColumn := 0

	// features
	X := encoding.RemoveColumn(data, labelColumn)
	// labels
	y := encoding.Float64ToInt641DArray(encoding.GetColumn(data, labelColumn))

	XStandardised := encoding.Standardise(X)
	XStandardised = encoding.Augment(XStandardised)

	N := len(X)
	N_64 := int64(N)
	d := int64(len(X[0]))

	k := 2
	precision := 1e2

	// gradient descent parameters
	lambda := 1.0
	step := 0.001
	maxIterations := 100
	initialWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}

	privKey, pubKey := libunlynx.GenKey()

	// compute all approximation coefficients per record
	approxCoefficients := make([][][]float64, N)
	for i := range X {
		approxCoefficients[i] = encoding.ComputeAllApproxCoefficients(XStandardised[i], y[i], k)
	}

	// aggregate the approximation coefficients locally
	aggregatedApproxCoefficients := encoding.AggregateApproxCoefficients(approxCoefficients)

	expected := encoding.FindMinimumWeights(aggregatedApproxCoefficients, initialWeights, N_64, lambda, step,
		maxIterations)

	initialWeights = []float64{0.1, 0.2, 0.3, 0.4, 0.5} // FindMinimumWeights modifies the initial weights...


	lrParameters := lib.LogisticRegressionParameters{FilePath: "", NbrRecords: N_64, NbrFeatures: d, Lambda: lambda, Step: step, MaxIterations: maxIterations,
		InitialWeights: initialWeights, K: 2, PrecisionApproxCoefficients: precision}

	resultEncrypted, _ := encoding.EncodeLogisticRegression(data, lrParameters, pubKey)
	result := encoding.DecodeLogisticRegression(resultEncrypted, privKey, lrParameters)

	// no equality because expected weights were computed in clear
	// todo: consider computed weights using encrypted approx coefficients
	//assert.Equal(t, expected, result)
	epsilon := 1e-4
	for i := 0; i < len(expected); i++ {
		assert.Equal(t, true, math.Abs(result[i]-expected[i]) < epsilon)
	}
}

func TestEncodeDecodeLogisticRegressionWithProofs(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	// data
	data := [][]float64{{0, 1.3, 5.0, 3.4, 3.2},
		{1, 2.0, 4.4, 4.2, 3.3},
		{1, 1.2, 1.9, 3.8, 2.3},
		{0, 1.0, 4.5, 2.2, 3.8},
		{1, 1.7, 2.8, 3.8, 2.7}}

	labelColumn := 0

	// features
	X := encoding.RemoveColumn(data, labelColumn)
	// labels
	y := encoding.Float64ToInt641DArray(encoding.GetColumn(data, labelColumn))

	XStandardised := encoding.Standardise(X)
	XStandardised = encoding.Augment(XStandardised)

	N := len(X)
	N_64 := int64(N)
	d := int64(len(X[0]))

	k := 2
	precision := 1e2

	// gradient descent parameters
	lambda := 1.0
	step := 0.001
	maxIterations := 100
	initialWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}

	privKey, pubKey := libunlynx.GenKey()

	// compute all approximation coefficients per record
	approxCoefficients := make([][][]float64, N)
	for i := range X {
		approxCoefficients[i] = encoding.ComputeAllApproxCoefficients(XStandardised[i], y[i], k)
	}

	// aggregate the approximation coefficients locally
	aggregatedApproxCoefficients := encoding.AggregateApproxCoefficients(approxCoefficients)

	expected := encoding.FindMinimumWeights(aggregatedApproxCoefficients, initialWeights, N_64, lambda, step,
		maxIterations)

	initialWeights = []float64{0.1, 0.2, 0.3, 0.4, 0.5} // FindMinimumWeights modifies the initial weights...


	lrParameters := lib.LogisticRegressionParameters{FilePath: "", NbrRecords: N_64, NbrFeatures: d, Lambda: lambda, Step: step, MaxIterations: maxIterations,
		InitialWeights: initialWeights, K: 2, PrecisionApproxCoefficients: precision}

	//signatures needed to check the proof; create signatures for 2 servers and all DPs outputs
	u := int64(2)
	l := int64(10)
	ps := make([][]lib.PublishSignature, 2)

	ranges := make([]*[]int64, 30)
	ps[0] = make([]lib.PublishSignature, 30)
	ps[1] = make([]lib.PublishSignature, 30)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 30)
	ys[1] = make([]kyber.Point, 30)
	for i := range ps[0] {
		ps[0][i] = lib.PublishSignatureBytesToPublishSignatures(lib.InitRangeProofSignature(u))
		ps[1][i] = lib.PublishSignatureBytesToPublishSignatures(lib.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, 30)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call


	resultEncrypted, clear, prf := encoding.EncodeLogisticRegressionWithProofs(data, lrParameters, pubKey, ps, ranges)
	result := encoding.DecodeLogisticRegression(resultEncrypted, privKey, lrParameters)

	for i := 0; i < 30; i++ {
		log.LLvl1(clear[i])
		log.LLvl1(lib.RangeProofVerification(lib.CreatePredicateRangeProofForAllServ(prf[i]), (*ranges[i])[0], (*ranges[i])[1], yss[i], pubKey))
	}
	// no equality because expected weights were computed in clear
	// todo: consider computed weights using encrypted approx coefficients
	//assert.Equal(t, expected, result)
	epsilon := 1e-4
	for i := 0; i < len(expected); i++ {
		assert.Equal(t, true, math.Abs(result[i]-expected[i]) < epsilon)
	}
}

func TestStandardise(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	X := [][]float64{
		{1.3, 5.0, 3.4, 3.2},
		{2.0, 4.4, 4.2, 3.3},
		{1.2, 1.9, 3.8, 2.3},
		{1.0, 4.5, 2.2, 3.8},
		{1.7, 2.8, 3.8, 2.7}}

	factor := 10.0
	XScaled := make([][]float64, len(X))

	for i := 0; i < len(X); i++ {
		XScaled[i] = make([]float64, len(X[i]))
		for j := 0; j < len(X[i]); j++ {
			XScaled[i][j] = factor * X[i][j]
		}
	}

	XStandardised := encoding.Standardise(X)
	XScaledStandardised := encoding.Standardise(XScaled)

	epsilon := 1e-12
	for i := 0; i < len(XStandardised); i++ {
		for j := 0; j < len(XStandardised[i]); j++ {
			assert.Equal(t, true, math.Abs(XStandardised[i][j]-XScaledStandardised[i][j]) < epsilon)
		}
	}

	//assert.Equal(t, XStandardised, XScaledStandardised)
}
