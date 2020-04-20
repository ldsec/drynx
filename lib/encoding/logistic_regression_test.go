package libdrynxencoding_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/cdipaolo/goml/base"
	"github.com/cdipaolo/goml/linear"
	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/encoding"
	"github.com/ldsec/drynx/lib/range"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat/combin"
)

func TestComputeApproxCoefficients(t *testing.T) {
	X := []float64{0, 1, 2, 3, 4}
	y := int64(1)
	k := 1
	expected := [][]float64{{0, 1, 2, 3, 4}}
	actual := libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 1
	expected = [][]float64{{0, -1, -2, -3, -4}}
	actual = libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(1)
	k = 2
	expected = [][]float64{
		{0, 1, 2, 3, 4},
		{0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16}}
	actual = libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 2
	expected = [][]float64{
		{0, -1, -2, -3, -4},
		{0, 0, 0, 0, 0, 1, 2, 3, 4, 4, 6, 8, 9, 12, 16}}
	actual = libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(1)
	k = 3
	expected = [][]float64{
		{0, 1, 2, 3, 4},
		{0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16, -8, -12, -16, -18, -24, -32, -27, -36, -48, -64}}
	actual = libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)

	X = []float64{0, 1, 2, 3, 4}
	y = int64(0)
	k = 3
	expected = [][]float64{
		{0, -1, -2, -3, -4},
		{0, 0, 0, 0, 0, 1, 2, 3, 4, 4, 6, 8, 9, 12, 16},
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -2, -3, -4, -4, -6, -8, -9, -12, -16, -8, -12, -16, -18, -24, -32, -27, -36, -48, -64}}
	actual = libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k)
	assert.Equal(t, expected, actual)
}

func TestComputeEncryptedApproxCoefficients(t *testing.T) {
	X := []float64{0, 1, 2, 3, 4}
	y := int64(1)
	k := 1

	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public

	expected := make([][]int64, k)
	actual := make([][]int64, k)

	approxCoeffs := libdrynxencoding.Float64ToInt642DArray(libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k))
	encryptedApproxCoeffs, _ := libdrynxencoding.ComputeEncryptedApproxCoefficients(approxCoeffs, pubKey)

	for j := 0; j < k; j++ {
		expected[j] = approxCoeffs[j]
		actual[j] = libunlynx.DecryptIntVector(privKey, libunlynx.EncryptIntVector(pubKey, approxCoeffs[j]))
	}

	assert.Equal(t, expected, actual)

	X = []float64{0, -1, -2, -3, -4}
	y = int64(0)
	k = 1

	approxCoeffs = libdrynxencoding.Float64ToInt642DArray(libdrynxencoding.ComputeDistinctApproxCoefficients(X, y, k))
	encryptedApproxCoeffs, _ = libdrynxencoding.ComputeEncryptedApproxCoefficients(approxCoeffs, pubKey)

	for j := 0; j < k; j++ {
		expected[j] = libunlynx.DecryptIntVector(privKey, encryptedApproxCoeffs[j])
		actual[j] = libunlynx.DecryptIntVector(privKey, libunlynx.EncryptIntVector(pubKey, approxCoeffs[j]))
	}

	assert.Equal(t, expected, actual)
}

func TestCombinationsWithRepetitionEfficient(t *testing.T) {
	//tests correctness and efficiency
	//int64 : -9223372036854775808 to 9223372036854775807

	n := int64(0)
	k := int64(0)
	expected := int64(1)
	actual := libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(4)
	expected = int64(1)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(-1)
	expected = int64(1)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(-1)
	k = int64(3)
	expected = int64(1)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(3)
	k = int64(1)
	expected = int64(3)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(5)
	k = int64(3)
	expected = int64(35)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(60)
	k = int64(10)
	expected = int64(340032449328)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(80)
	k = int64(10)
	expected = int64(5085018206136)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(100)
	k = int64(10)
	expected = int64(42634215112710)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	n = int64(200)
	k = int64(10)
	expected = int64(35216131179263320)
	actual = libdrynxencoding.CombinationsWithRepetition(n, k)
	assert.Equal(t, expected, actual)

	//possibly overflows int64 during the computation
	//n = int64(300)
	//k = int64(10)
	//expected = int64(1887629299319420580)
	//actual = encoding.libdrynxencoding.CombinationsWithRepetition(n, k)
	//assert.Equal(t, expected, actual)
}

func TestAggregateEncryptedApproxCoefficients(t *testing.T) {
	// data providers data
	X := [][]float64{{0, 1, 2, 3, 4}, {0, 1, 2, 3, 4}}
	y := []int64{1, 1}
	k := 1
	N := len(X)

	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public

	approxCoefficients := make([][][]float64, N)
	encryptedApproxCoefficients := make([][]*libunlynx.CipherVector, N)

	// compute the approximation coefficients and encrypt them
	for i := 0; i < N; i++ {
		approxCoefficients[i] = libdrynxencoding.ComputeAllApproxCoefficients(X[i], y[i], k)
		encryptedApproxCoefficients[i], _ = libdrynxencoding.ComputeEncryptedApproxCoefficients(
			libdrynxencoding.Float64ToInt642DArray(approxCoefficients[i]), pubKey)
	}

	// aggregate the encrypted approximation coefficients
	actual := libdrynxencoding.AggregateEncryptedApproxCoefficients(encryptedApproxCoefficients)
	// aggregate the approximation coefficients
	expected := libdrynxencoding.Float64ToInt642DArray(libdrynxencoding.AggregateApproxCoefficients(approxCoefficients))

	// compare the decrypted aggregated approximation coefficients
	for j := 0; j < k; j++ {
		assert.Equal(t, expected[j], libunlynx.DecryptIntVector(privKey, actual[j]))
	}
}

func TestPredictWithInt(t *testing.T) {

	// integer weights
	X := []float64{0, 1, 2, 3, 4}
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public
	libunlynx.CreateDecryptionTable(10000, pubKey, privKey)
	encryptedData := libunlynx.EncryptIntVector(pubKey, libdrynxencoding.Float64ToInt641DArray(X))
	precision := 1e1

	weights := []float64{1, 2, 3, 4, 5, 6}
	actual := libdrynxencoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected := libdrynxencoding.PredictInClear(X, weights)
	assert.Equal(t, expected, actual)
}

func TestPredictWithFloat(t *testing.T) {
	X := []float64{0, 1, 2, 3, 4}
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public
	encryptedData := libunlynx.EncryptIntVector(pubKey, libdrynxencoding.Float64ToInt641DArray(X))
	precision := 1e1

	// used to defined the maximal error allowed (?)
	ratio := 0.01

	// float weights
	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6}
	actual := libdrynxencoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected := libdrynxencoding.PredictInClear(X, weights)
	epsilon := expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{0.5, 0.5, 0.5, 0.5, 0.5, 0.5}
	actual = libdrynxencoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = libdrynxencoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{1.2, 2.4, 3.4, 4.6, 4.5, 1.4}
	actual = libdrynxencoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = libdrynxencoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	//showDetails(expected, actual, epsilon)

	weights = []float64{-1.2, -2.4, -3.4, 4.6, 4.5, 1.4}
	actual = libdrynxencoding.Predict(*encryptedData, weights, privKey, precision, 1)
	expected = libdrynxencoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)
}

func TestPredictWithIntHomomorphic(t *testing.T) {
	// integer weights
	X := []float64{0, 1, 2, 3, 4}
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public
	encryptedData := libunlynx.EncryptIntVector(pubKey, libdrynxencoding.Float64ToInt641DArray(X))

	weights := []float64{1, 2, 3, 4, 5, 6}
	actual := libdrynxencoding.PredictHomomorphic(*encryptedData, weights, privKey, 1, 1)
	expected := libdrynxencoding.PredictInClear(X, weights)
	assert.Equal(t, expected, actual)
	showDetails(expected, actual, 0)
}

func TestPredictWithFloatHomomorphic(t *testing.T) {
	X := []float64{1, 2, 6, 5, 5}
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public
	encryptedData := libunlynx.EncryptIntVector(pubKey, libdrynxencoding.Float64ToInt641DArray(X))

	// used to defined the maximal error allowed (?)
	ratio := 0.01

	// float weights
	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6}
	actual := libdrynxencoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e1, 1e0)
	expected := libdrynxencoding.PredictInClear(X, weights)
	epsilon := expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{0.1111, 0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = libdrynxencoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e3, 1e0)
	expected = libdrynxencoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{0.1111, 0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = libdrynxencoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e4, 1e0)
	expected = libdrynxencoding.PredictInClear(X, weights)
	epsilon = expected * ratio
	assert.Equal(t, true, math.Abs(actual-expected) < epsilon)
	showDetails(expected, actual, epsilon)

	// float weights
	weights = []float64{-0.1111, -0.2222, 0.3333, 0.4444, 0.5555, 0.6666}
	actual = libdrynxencoding.PredictHomomorphic(*encryptedData, weights, privKey, 1e4, 1e0)
	expected = libdrynxencoding.PredictInClear(X, weights)
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
	arrayInt64 := []int64{0, 1, 2, 3, 4}
	expected := []float64{0.0, 1.0, 2.0, 3.0, 4.0}
	actual := libdrynxencoding.Int64ToFloat641DArray(arrayInt64)
	assert.Equal(t, expected, actual)
}

func TestInt64ToFloat642DArray(t *testing.T) {
	arrayInt64 := [][]int64{{0, 1, 2, 3, 4}, {5, 6, 7, 8, 9}}
	expected := [][]float64{{0.0, 1.0, 2.0, 3.0, 4.0}, {5.0, 6.0, 7.0, 8.0, 9.0}}
	actual := libdrynxencoding.Int64ToFloat642DArray(arrayInt64)
	assert.Equal(t, expected, actual)
}

func TestGradient(t *testing.T) {
	X := [][]float64{{1, 2, 3, 4, 5}}
	y := []int64{1}
	k := 1
	N := len(X) //len(X[0]) * 10

	lambda := 10.0
	step := 0.0001
	maxIterations := 100000

	weights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}
	approxCoeffs := libdrynxencoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	// libdrynxencoding.Gradient for k = 1
	expected := make([]float64, len(weights))
	for i := 0; i < len(weights); i++ {
		expected[i] = (1 / float64(N)) * libdrynxencoding.PolyApproxCoefficients[k] * float64(approxCoeffs[k-1][i])
		if i >= 0 {
			expected[i] += (lambda / float64(N)) * weights[i]
		}
	}
	actual := libdrynxencoding.Gradient(weights, approxCoeffs, k, int64(N), lambda)
	assert.Equal(t, expected[1:], actual[1:])

	// libdrynxencoding.Gradient for k = 2
	k = 2
	approxCoeffs = libdrynxencoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	expected = libdrynxencoding.GradientFor2(weights, approxCoeffs, k, N, lambda)
	actual = libdrynxencoding.Gradient(weights, approxCoeffs, k, int64(N), lambda)
	assert.Equal(t, expected[1:], actual[1:])

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
	X := [][]float64{{1, 0, 1, 2, 3, 4}}
	y := []int64{1}
	k := 1
	N := len(X)

	lambda := 1.0

	approxCoeffs := libdrynxencoding.ComputeAllApproxCoefficients(X[0], y[0], k)
	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := libdrynxencoding.AggregateApproxCoefficients(allApproxCoeffs)

	weights := []float64{0, 1, 2, 3, 4, 5}

	expectedCost := 0.0
	for i := 0; i < len(weights); i++ {
		expectedCost += weights[i] * float64(aggregatedApproxCoeffs[0][i])
	}
	expectedCost *= (1 / float64(N)) * libdrynxencoding.PolyApproxCoefficients[k]
	expectedCost -= libdrynxencoding.PolyApproxCoefficients[0]

	// l2-regularizer contribution
	for i := 0; i < len(weights); i++ {
		expectedCost += weights[i] * weights[i] * (lambda / 2 * float64(N))
	}

	actuaCost := libdrynxencoding.Cost(weights, aggregatedApproxCoeffs, int64(N), lambda)

	assert.Equal(t, expectedCost, actuaCost)
}

func TestLogisticCost(t *testing.T) {
	X := [][]float64{{1.0, 0.0, 1.0, 2.0, 3.0, 4.0}}
	y := []int64{1}
	N := int64(1)

	lambda := 1.0

	weights := []float64{0.035, 0.00000, 0.03712, 0.07425, 0.11137, 0.14849}
	expected := 0.29668003759705
	actual := libdrynxencoding.LogisticRegressionCost(weights, X, y, N, lambda)
	assert.Equal(t, expected, actual)
}

func TestFindMinimumWeightsDegreeOne(t *testing.T) {
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

	approxCoeffs := libdrynxencoding.ComputeAllApproxCoefficients(X[0], y[0], k)
	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := libdrynxencoding.AggregateApproxCoefficients(allApproxCoeffs)

	expectedWeights := libdrynxencoding.ComputeMinimumWeights(aggregatedApproxCoeffs, lambda)
	actualWeights := libdrynxencoding.FindMinimumWeights(aggregatedApproxCoeffs, initialWeights, N, lambda, step,
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

	costActualWeights := libdrynxencoding.Cost(actualWeights, aggregatedApproxCoeffs, N, lambda)
	costExpectedWeights := libdrynxencoding.Cost(expectedWeights, aggregatedApproxCoeffs, N, lambda)
	fmt.Println("libdrynxencoding.Cost expected weights:", costExpectedWeights)
	fmt.Println("libdrynxencoding.Cost actual weights:", costActualWeights)

	testX := make([][]float64, 1)
	testX[0] = X[0][1:]
	testY := []float64{float64(y[0])}
	model := linear.NewLogistic(base.BatchGA, step, lambda, maxIterations, testX, testY)
	fmt.Println(model.Learn())
}

func TestFindMinimumWeights(t *testing.T) {
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

	approxCoeffs := libdrynxencoding.ComputeAllApproxCoefficients(X[0], y[0], k)

	allApproxCoeffs := make([][][]float64, N)
	allApproxCoeffs[0] = approxCoeffs
	aggregatedApproxCoeffs := libdrynxencoding.AggregateApproxCoefficients(allApproxCoeffs)

	weights := libdrynxencoding.FindMinimumWeights(aggregatedApproxCoeffs, initialWeights, N, lambda, step, maxIterations)
	Cost := libdrynxencoding.Cost(weights, aggregatedApproxCoeffs, N, lambda)
	logisticCost := libdrynxencoding.LogisticRegressionCost(weights, X, y, N, lambda)

	fmt.Println("approx. coeffs.:", approxCoeffs)
	fmt.Println("weights:", weights)
	fmt.Println("libdrynxencoding.Cost:", Cost)
	fmt.Println("logistic libdrynxencoding.Cost:", logisticCost)
	fmt.Println()

	testX := make([][]float64, 1)
	testX[0] = X[0][1:]
	testY := []float64{float64(y[0])}
	model := linear.NewLogistic(base.BatchGA, step, lambda, maxIterations, testX, testY)

	fmt.Println(model.Learn())
	weightsPackage := []float64{0.035, 0.00000, 0.03712, 0.07425, 0.11137, 0.14849}
	fmt.Println("libdrynxencoding.Cost:", libdrynxencoding.Cost(weightsPackage, approxCoeffs, N, lambda))
	fmt.Println("logistic libdrynxencoding.Cost:", libdrynxencoding.LogisticRegressionCost(weightsPackage, X, y, N, lambda))
}

func TestRange(t *testing.T) {
	expected := []int64{0, 1, 2, 3, 4, 5}
	actual := libdrynxencoding.Range(0, 6)
	assert.Equal(t, expected, actual)

	expected = []int64{10, 11, 12, 13}
	actual = libdrynxencoding.Range(10, 14)
	assert.Equal(t, expected, actual)
}

func TestCombinations(t *testing.T) {
	result := combin.Cartesian([]int{3, 3, 3})
	fmt.Println(result)
}

func TestCartesianProduct(t *testing.T) {
	start := int64(0)
	end := int64(2)
	dim := 3
	actual := libdrynxencoding.CartesianProduct(start, end, dim)
	expected := [][]int64{{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1}, {1, 0, 0}, {1, 0, 1}, {1, 1, 0}, {1, 1, 1}}
	assert.Equal(t, expected, actual)

	start = int64(0)
	end = int64(3)
	dim = 2
	actual = libdrynxencoding.CartesianProduct(start, end, dim)
	expected = [][]int64{{0, 0}, {0, 1}, {0, 2}, {1, 0}, {1, 1}, {1, 2}, {2, 0}, {2, 1}, {2, 2}}
	assert.Equal(t, expected, actual)
}

func TestAddSub(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public
	libunlynx.CreateDecryptionTable(int64(10000), pubKey, privKey)
	ct := libunlynx.NewCipherText()

	m := int64(6)
	otherCt := libunlynx.EncryptInt(pubKey, m)

	ct.Add(*ct, *otherCt)
	pt := libunlynx.DecryptIntWithNeg(privKey, *ct)

	assert.Equal(t, pt, m)
}

func TestEncodeDecodeLogisticRegression(t *testing.T) {
	// features
	matrixX := mat.NewDense(5, 4, nil)
	matrixX.SetRow(0, []float64{1.3, 5.0, 3.4, 3.2})
	matrixX.SetRow(1, []float64{2.0, 4.4, 4.2, 3.3})
	matrixX.SetRow(2, []float64{1.2, 1.9, 3.8, 2.3})
	matrixX.SetRow(3, []float64{1.0, 4.5, 2.2, 3.8})
	matrixX.SetRow(4, []float64{1.7, 2.8, 3.8, 2.7})

	// labels
	yFloat := mat.NewVecDense(5, []float64{0, 1, 1, 0, 1})
	y := libdrynxencoding.VectorToInt(yFloat)

	// dimensions
	N, d := matrixX.Dims()

	// standarized
	matrixXStandardised := mat.NewDense(N, d, nil)
	matrixXStandardised.Copy(matrixX)
	libdrynxencoding.Standardise(matrixXStandardised)
	matrixXStandardised = libdrynxencoding.Augment(matrixXStandardised)
	XStandardised := libdrynxencoding.MatrixToFloat2D(matrixXStandardised)

	k := 2
	precision := 1e2

	// libdrynxencoding.Gradient descent parameters
	lambda := 1.0
	step := 0.001
	maxIterations := 100
	initialWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}

	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public

	// compute all approximation coefficients per record
	approxCoefficients := make([][][]float64, N)
	for i := range approxCoefficients {
		approxCoefficients[i] = libdrynxencoding.ComputeAllApproxCoefficients(XStandardised[i], y[i], k)
	}

	// aggregate the approximation coefficients locally
	aggregatedApproxCoefficients := libdrynxencoding.AggregateApproxCoefficients(approxCoefficients)

	expected := libdrynxencoding.FindMinimumWeights(aggregatedApproxCoefficients, initialWeights, int64(N), lambda, step,
		maxIterations)

	initialWeights = []float64{0.1, 0.2, 0.3, 0.4, 0.5} // libdrynxencoding.FindMinimumWeights modifies the initial weights...

	lrParameters := libdrynx.LogisticRegressionParameters{FilePath: "", NbrRecords: int64(N), NbrFeatures: int64(d), Lambda: lambda, Step: step, MaxIterations: maxIterations,
		InitialWeights: initialWeights, K: 2, PrecisionApproxCoefficients: precision}

	X := libdrynxencoding.MatrixToFloat2D(matrixX)
	resultEncrypted, _, err := libdrynxencoding.EncodeLogisticRegression(X, y, lrParameters, pubKey)
	require.NoError(t, err)
	result := libdrynxencoding.DecodeLogisticRegression(resultEncrypted, privKey, lrParameters)

	// no equality because expected weights were computed in clear
	// todo: consider computed weights using encrypted approx coefficients
	//assert.Equal(t, expected, result)
	epsilon := 1e-4
	for i := 0; i < len(expected); i++ {
		assert.Equal(t, true, math.Abs(result[i]-expected[i]) < epsilon)
	}
}

func TestEncodeDecodeLogisticRegressionWithProofs(t *testing.T) {
	// features
	matrixX := mat.NewDense(5, 4, nil)
	matrixX.SetRow(0, []float64{1.3, 5.0, 3.4, 3.2})
	matrixX.SetRow(1, []float64{2.0, 4.4, 4.2, 3.3})
	matrixX.SetRow(2, []float64{1.2, 1.9, 3.8, 2.3})
	matrixX.SetRow(3, []float64{1.0, 4.5, 2.2, 3.8})
	matrixX.SetRow(4, []float64{1.7, 2.8, 3.8, 2.7})

	// labels
	yFloat := mat.NewVecDense(5, []float64{0, 1, 1, 0, 1})
	y := libdrynxencoding.VectorToInt(yFloat)

	// dimensions
	N, d := matrixX.Dims()

	// standarized
	matrixXStandardised := mat.NewDense(N, d, nil)
	matrixXStandardised.Copy(matrixX)
	libdrynxencoding.Standardise(matrixXStandardised)
	matrixXStandardised = libdrynxencoding.Augment(matrixXStandardised)
	XStandardised := libdrynxencoding.MatrixToFloat2D(matrixXStandardised)

	k := 2
	precision := 1e2

	// libdrynxencoding.Gradient descent parameters
	lambda := 1.0
	step := 0.001
	maxIterations := 100
	initialWeights := []float64{0.1, 0.2, 0.3, 0.4, 0.5}

	keys := key.NewKeyPair(libunlynx.SuiTe)
	privKey, pubKey := keys.Private, keys.Public

	// compute all approximation coefficients per record
	approxCoefficients := make([][][]float64, N)
	for i := range approxCoefficients {
		approxCoefficients[i] = libdrynxencoding.ComputeAllApproxCoefficients(XStandardised[i], y[i], k)
	}

	// aggregate the approximation coefficients locally
	aggregatedApproxCoefficients := libdrynxencoding.AggregateApproxCoefficients(approxCoefficients)

	expected := libdrynxencoding.FindMinimumWeights(aggregatedApproxCoefficients, initialWeights, int64(N), lambda, step,
		maxIterations)

	initialWeights = []float64{0.1, 0.2, 0.3, 0.4, 0.5} // libdrynxencoding.FindMinimumWeights modifies the initial weights...

	lrParameters := libdrynx.LogisticRegressionParameters{FilePath: "", NbrRecords: int64(N), NbrFeatures: int64(d), Lambda: lambda, Step: step, MaxIterations: maxIterations,
		InitialWeights: initialWeights, K: 2, PrecisionApproxCoefficients: precision}

	//signatures needed to check the proof; create signatures for 2 servers and all DPs outputs
	u := int64(4)
	l := int64(10)
	ps := make([][]libdrynx.PublishSignature, 2)

	ranges := make([]*[]int64, 30)
	ps[0] = make([]libdrynx.PublishSignature, 30)
	ps[1] = make([]libdrynx.PublishSignature, 30)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 30)
	ys[1] = make([]kyber.Point, 30)
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
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

	X := libdrynxencoding.MatrixToFloat2D(matrixX)
	resultEncrypted, _, prf, err := libdrynxencoding.EncodeLogisticRegressionWithProofs(X, y, lrParameters, pubKey, ps, ranges)
	require.NoError(t, err)
	result := libdrynxencoding.DecodeLogisticRegression(resultEncrypted, privKey, lrParameters)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[0]), (*ranges[0])[0], (*ranges[0])[1], yss[0], pubKey))

	// no equality because expected weights were computed in clear
	// todo: consider computed weights using encrypted approx coefficients
	//assert.Equal(t, expected, result)
	epsilon := 1e-4
	for i := 0; i < len(expected); i++ {
		assert.Equal(t, true, math.Abs(result[i]-expected[i]) < epsilon)
	}
}

func TestStandardise(t *testing.T) {
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

	matrixXStandardised := libdrynxencoding.Float2DToMatrix(X)
	libdrynxencoding.Standardise(matrixXStandardised)
	matrixXStandardised = libdrynxencoding.Augment(matrixXStandardised)
	XStandardised := libdrynxencoding.MatrixToFloat2D(matrixXStandardised)

	matrixXScaledStandardised := libdrynxencoding.Float2DToMatrix(X)
	libdrynxencoding.Standardise(matrixXScaledStandardised)
	matrixXScaledStandardised = libdrynxencoding.Augment(matrixXScaledStandardised)
	XScaledStandardised := libdrynxencoding.MatrixToFloat2D(matrixXScaledStandardised)

	epsilon := 1e-12
	for i := 0; i < len(XStandardised); i++ {
		for j := 0; j < len(XStandardised[i]); j++ {
			assert.InEpsilon(t, XStandardised[i][j], XScaledStandardised[i][j], epsilon)
		}
	}

	//assert.Equal(t, XStandardised, XScaledStandardised)
}
