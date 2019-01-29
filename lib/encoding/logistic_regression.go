package encoding

import (
	"bufio"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"github.com/montanaflynn/stats"
	"gonum.org/v1/gonum/integrate"
	"gonum.org/v1/gonum/stat"
	"gonum.org/v1/gonum/stat/combin"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

// TaylorCoefficients are the taylor coefficients (first taylor expansion coefficients of ln(1/(1+exp(x)))
var TaylorCoefficients = []float64{-math.Log(2), -0.5, -0.125, 0, 0.0052}

// MinAreaCoefficients are the min area coefficients
var MinAreaCoefficients = []float64{-0.714761, -0.5, -0.0976419}

// PolyApproxCoefficients is the number of approximated coefficients
var PolyApproxCoefficients = MinAreaCoefficients

// -------------------------
// UnLynx framework specific
// -------------------------

// EncodeLogisticRegression computes and encrypts the data provider's coefficients for logistic regression
func EncodeLogisticRegression(data [][]float64, lrParameters libdrynx.LogisticRegressionParameters, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	d := lrParameters.NbrFeatures
	n := GetTotalNumberApproxCoefficients(d, lrParameters.K)

	aggregatedApproxCoefficientsIntPacked := make([]int64, n)
	encryptedAggregatedApproxCoefficients := make([]libunlynx.CipherText, n)

	if data != nil && len(data) > 0 {
		// unpack the data into features and labels
		labelColumn := d
		X := RemoveColumn(data, labelColumn)
		y := Float64ToInt641DArray(GetColumn(data, labelColumn))


		// standardise the data
		var XStandardised [][]float64
		if lrParameters.Means != nil && lrParameters.StandardDeviations != nil &&
			len(lrParameters.Means) > 0 && len(lrParameters.StandardDeviations) > 0 {
			// using global means and standard deviations, if given
			log.Lvl2("Standardising the training set with global means and standard deviations...")
			XStandardised = StandardiseWith(X, lrParameters.Means, lrParameters.StandardDeviations)
		} else {
			// using local means and standard deviations, if not given
			log.Lvl2("Standardising the training set with local means and standard deviations...")
			XStandardised = Standardise(X)
		}

		// add an all 1s column to the data (offset term)
		XStandardised = Augment(XStandardised)

		N := lrParameters.NbrRecords

		// compute all approximation coefficients per record
		approxCoefficients := make([][][]float64, N)
		for i := 0; i < len(XStandardised); i++ {
			approxCoefficients[i] = ComputeAllApproxCoefficients(XStandardised[i], y[i], lrParameters.K)
		}
		// aggregate the approximation coefficients locally
		aggregatedApproxCoefficients := AggregateApproxCoefficients(approxCoefficients)
		// convert (and optionally scale) the aggregated approximation coefficients to int
		aggregatedApproxCoefficientsInt := Float64ToInt642DArrayWithPrecision(aggregatedApproxCoefficients, lrParameters.PrecisionApproxCoefficients)
		// encrypt the aggregated approximation coefficients
		encryptedApproxCoefficients, _ := ComputeEncryptedApproxCoefficients(aggregatedApproxCoefficientsInt, pubKey)

		nLevelPrevious := getNumberApproxCoefficients(d, -1)
		for j := int64(0); j < lrParameters.K; j++ {
			nLevel := getNumberApproxCoefficients(d, j)
			for i := int64(0); i < nLevel; i++ {
				// pack the encrypted aggregated approximation coefficients (will need to unpack the result at the querier side)
				encryptedAggregatedApproxCoefficients[j*nLevelPrevious+i] = (*encryptedApproxCoefficients[j])[i]
				// pack the aggregated approximation coefficients
				aggregatedApproxCoefficientsIntPacked[j*nLevelPrevious+i] = aggregatedApproxCoefficientsInt[j][i]
			}
			nLevelPrevious = nLevel
		}
	}

	log.LLvl2("Aggregated approximation coefficients:", aggregatedApproxCoefficientsIntPacked)
	log.LLvl2("Number of aggregated approximation coefficients:", len(aggregatedApproxCoefficientsIntPacked))
	return encryptedAggregatedApproxCoefficients, aggregatedApproxCoefficientsIntPacked
}

// CipherAndRandom contains one ciphertext and the scalar used in its encryption
type CipherAndRandom struct {
	C libunlynx.CipherText
	r kyber.Scalar
}

// EncodeLogisticRegressionWithProofs computes and encrypts the data provider's coefficients for logistic regression with range proofs
func EncodeLogisticRegressionWithProofs(data [][]float64, lrParameters libdrynx.LogisticRegressionParameters, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	d := lrParameters.NbrFeatures
	n := GetTotalNumberApproxCoefficients(d, lrParameters.K)

	aggregatedApproxCoefficientsIntPacked := make([]int64, n)
	encryptedAggregatedApproxCoefficients := make([]CipherAndRandom, n)
	encryptedAggregatedApproxCoefficientsOnlyCipher := make([]libunlynx.CipherText, n)

	if data != nil && len(data) > 0 {
		// unpack the data into features and labels
		labelColumn := d
		X := RemoveColumn(data, labelColumn)
		y := Float64ToInt641DArray(GetColumn(data, labelColumn))

		// standardise the data
		var XStandardised [][]float64
		if lrParameters.Means != nil && lrParameters.StandardDeviations != nil &&
			len(lrParameters.Means) > 0 && len(lrParameters.StandardDeviations) > 0 {
			// using global means and standard deviations, if given
			log.Lvl2("Standardising the training set with global means and standard deviations...")
			XStandardised = StandardiseWith(X, lrParameters.Means, lrParameters.StandardDeviations)
		} else {
			// using local means and standard deviations, if not given
			log.Lvl2("Standardising the training set with local means and standard deviations...")
			XStandardised = Standardise(X)
		}

		// add an all 1s column to the data (offset term)
		XStandardised = Augment(XStandardised)

		N := lrParameters.NbrRecords

		// compute all approximation coefficients per record
		approxCoefficients := make([][][]float64, N)
		for i := 0; i < len(XStandardised); i++ {
			approxCoefficients[i] = ComputeAllApproxCoefficients(XStandardised[i], y[i], lrParameters.K)
		}

		// aggregate the approximation coefficients locally
		aggregatedApproxCoefficients := AggregateApproxCoefficients(approxCoefficients)
		// convert (and optionally scale) the aggregated approximation coefficients to int
		aggregatedApproxCoefficientsInt := Float64ToInt642DArrayWithPrecision(aggregatedApproxCoefficients, lrParameters.PrecisionApproxCoefficients)
		// encrypt the aggregated approximation coefficients
		encryptedApproxCoefficients, encryptedApproxCoefficientsRs := ComputeEncryptedApproxCoefficients(aggregatedApproxCoefficientsInt, pubKey)

		nLevelPrevious := getNumberApproxCoefficients(d, -1)
		for j := int64(0); j < lrParameters.K; j++ {
			nLevel := getNumberApproxCoefficients(d, j)
			for i := int64(0); i < nLevel; i++ {
				// pack the encrypted aggregated approximation coefficients (will need to unpack the result at the querier side)
				encryptedAggregatedApproxCoefficients[j*nLevelPrevious+i].C = (*encryptedApproxCoefficients[j])[i]
				encryptedAggregatedApproxCoefficients[j*nLevelPrevious+i].r = (encryptedApproxCoefficientsRs[j])[i]
				encryptedAggregatedApproxCoefficientsOnlyCipher[j*nLevelPrevious+i] = (*encryptedApproxCoefficients[j])[i]
				// pack the aggregated approximation coefficients
				aggregatedApproxCoefficientsIntPacked[j*nLevelPrevious+i] = aggregatedApproxCoefficientsInt[j][i]
			}
			nLevelPrevious = nLevel
		}
	}

	log.LLvl2("Aggregated approximation coefficients:", aggregatedApproxCoefficientsIntPacked)
	log.LLvl2("Number of aggregated approximation coefficients:", len(aggregatedApproxCoefficientsIntPacked))

	createRangeProof := make([]libdrynx.CreateProof, len(aggregatedApproxCoefficientsIntPacked))
	wg1 := libunlynx.StartParallelize(len(aggregatedApproxCoefficientsIntPacked))
	for i, v := range aggregatedApproxCoefficientsIntPacked {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createRangeProof[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: encryptedAggregatedApproxCoefficients[i].r, CaPub: pubKey, Cipher: encryptedAggregatedApproxCoefficients[i].C}
			}(i, v)
		} else {
			//input range validation proof
			createRangeProof[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: encryptedAggregatedApproxCoefficients[i].r, CaPub: pubKey, Cipher: encryptedAggregatedApproxCoefficients[i].C}
		}
	}
	libunlynx.EndParallelize(wg1)
	return encryptedAggregatedApproxCoefficientsOnlyCipher, aggregatedApproxCoefficientsIntPacked, createRangeProof
}

// DecodeLogisticRegression decodes the logistic regression approximation coefficients (querier side)
func DecodeLogisticRegression(result []libunlynx.CipherText, privKey kyber.Scalar,
	lrParameters libdrynx.LogisticRegressionParameters) []float64 {

	N := lrParameters.NbrRecords
	d := lrParameters.NbrFeatures

	k := lrParameters.K
	precision := lrParameters.PrecisionApproxCoefficients

	initialWeights := lrParameters.InitialWeights
	lambda := lrParameters.Lambda
	step := lrParameters.Step
	maxIterations := lrParameters.MaxIterations

	nbrApproxCoefficients := len(result)
	approxCoefficientsPacked := make([]int64, nbrApproxCoefficients)

	decryption := libunlynx.StartTimer("Decryption")
	// decrypt the encrypted aggregated approximation coefficients
	for i := 0; i < len(result); i++ {approxCoefficientsPacked[i] = libunlynx.DecryptIntWithNeg(privKey, result[i])}
	libunlynx.EndTimer(decryption)

	gradientDescent := libunlynx.StartTimer("GradientDescent")
	// unpack the aggregated approximation coefficients
	approxCoefficients := make([][]int64, k)
	nLevelPrevious := getNumberApproxCoefficients(d,-1)
	for j := int64(0); j < k; j++ {
		nLevel := getNumberApproxCoefficients(d, j)
		//nLevelPrevious := getNumberApproxCoefficients(d, j-1)
		approxCoefficients[j] = make([]int64, nLevel)
		for i := int64(0); i < nLevel; i++ {approxCoefficients[j][i] = approxCoefficientsPacked[j*nLevelPrevious+i]}
		nLevelPrevious = nLevel
	}

	log.LLvl2("Number of approximation coefficients:", len(approxCoefficientsPacked))
	log.LLvl2("Decrypted approximation coefficients:", approxCoefficientsPacked)

	// convert the (aggregated) approximation coefficients to float
	approxCoefficientsFloat := Int64ToFloat642DArray(approxCoefficients)

	// rescale to the original order of magnitude
	for j := 0; int64(j) < k; j++ {
		for i := 0; i < len(approxCoefficientsFloat[j]); i++ {
			approxCoefficientsFloat[j][i] = approxCoefficientsFloat[j][i] / precision
		}
	}

	// compute the weights of the homomorphism-aware logistic regression
	weights := FindMinimumWeights(approxCoefficientsFloat, initialWeights, N, lambda, step, maxIterations)
	libunlynx.EndTimer(gradientDescent)

	return weights
}

// Factorial computes the factorial of the given integer
func Factorial(n int64) (result int64) {
	if n > 0 {
		result = n * Factorial(n-1)
		return result
	}
	return 1
}

// CombinationsWithRepetition computes the number of combinations with repetition of k elements from a set of n elements,
// i.e. Factorial(n+k-1) / (Factorial(k) * Factorial(n-1))
func CombinationsWithRepetition(n int64, k int64) int64 {
	numerator := int64(1)
	denominator := int64(Factorial(k))
	divisor := int64(2)

	if k <= n {
		for i := int64(1); i <= k; i++ {
			numerator = numerator * (n + k - i)
			for (divisor <= k) && (numerator%divisor == 0) && (denominator%divisor == 0) {
				numerator /= divisor
				denominator /= divisor
				divisor++
			}
		}
		return numerator / denominator
	}
	return 1
}

// getTotalNumberApproxCoefficients returns the total number of approximation coefficients to compute for <d> features and approximation degree <k>
func GetTotalNumberApproxCoefficients(d int64, k int64) int64 {
	count := int64(0)
	for j := int64(0); j < k; j++ {count += getNumberApproxCoefficients(d, j)}
	return count
}

// getNumberApproxCoefficients returns the number of approximation coefficients to compute for <d> features at approximation degree <level>
func getNumberApproxCoefficients(d int64, level int64) int64 {return int64(math.Pow(float64(d+1), float64(level+1)))}

// ComputeDistinctApproxCoefficients computes the distinct coefficients of the approximated logistic regression cost function
func ComputeDistinctApproxCoefficients(X []float64, y int64, k int64) [][]float64 {
	d := len(X) - 1 // the dimension of the data

	// case k <= 3 ok
	// we store only the distinct coefficients
	approxCoeffs := make([][]float64, k)
	for j := int64(0); j < k; j++ {
		approxCoeffs[j] = make([]float64, CombinationsWithRepetition(int64(d+1), int64(j+1)))
	}

	// initialisation: computation of the coefficients for k = 1
	for s := 0; s <= d; s++ {approxCoeffs[0][s] = X[s] * (2*float64(y) - 1)}

	// computation of the coefficients for k >= 2
	for j := int64(1); j < k; j++ {
		totalNumberCoeffs := len(approxCoeffs[j])

		ypart := y - y*int64(math.Pow(-1, float64(j+1))) - 1

		idx1 := 0
		idx2 := 0

		c := CombinationsWithRepetition(int64(d+1-idx2), int64(j))
		cPrev := c

		for ri := 0; ri < int(totalNumberCoeffs); ri++ {
			approxCoeffs[j][ri] = approxCoeffs[j-1][idx1] * X[idx2] * float64(ypart)

			idx1++
			c--
			if c == 0 {
				idx2++
				c = CombinationsWithRepetition(int64(d+1-idx2), int64(j))
				idx1 = int(cPrev - c)
			}
		}
	}

	return approxCoeffs
}

// ComputeAllApproxCoefficients computes all the coefficients of the approximated logistic regression cost function
func ComputeAllApproxCoefficients(X []float64, y int64, k int64) [][]float64 {
	d := len(X) - 1 // the dimension of the data

	approxCoefficients := make([][]float64, k)
	for j := int64(0); j < k; j++ {approxCoefficients[j] = make([]float64, getNumberApproxCoefficients(int64(d), j))}

	// initialisation: computation of the coefficients for j = 1
	for s := 0; s <= d; s++ {approxCoefficients[0][s] = X[s] * (2*float64(y) - 1)}

	// computation of the coefficients for j >= 2
	for j := int64(2); int64(j) <= k; j++ {
		ypart := float64(y - y*int64(math.Pow(-1, float64(j))) - 1)

		// generate all indices combinations with repetitions, order matters, of size j (cartesian product)
		combinations := CartesianProduct(0, int64(d+1), j)

		// compute the product of the Xs for each combination of indices
		for ri := 0; ri < len(combinations); ri++ {
			XProduct := 1.0
			combination := combinations[ri]
			for i := 0; i < len(combination); i++ {XProduct *= X[int(combination[i])]}
			approxCoefficients[j-1][ri] = ypart * XProduct
		}
	}
	return approxCoefficients
}

// ComputeEncryptedApproxCoefficients computes the ElGamal encryption of the coefficients of the approximated logistic regression cost function
func ComputeEncryptedApproxCoefficients(approxCoefficients [][]int64, pubKey kyber.Point) ([]*libunlynx.CipherVector, [][]kyber.Scalar) {
	k := len(approxCoefficients) // the logarithm function approximation degree
	// log.LLvl1(approxCoefficients[1][11])
	encryptedApproxCoefficients := make([]*libunlynx.CipherVector, k)
	encryptedApproxCoefficientsRs := make([][]kyber.Scalar, k)
	wg := libunlynx.StartParallelize(k)
	for j := 0; j < k; j++ {
		go func(j int) {
			defer wg.Done()
			for i := 0; i < len(approxCoefficients[j]); i++ {
				if approxCoefficients[j][i] > libunlynx.MaxHomomorphicInt {
					log.Fatalf("Error: %d exceeds %d", approxCoefficients[i][j], libunlynx.MaxHomomorphicInt)
				}
			}
			tmpCv, tmpRs := libunlynx.EncryptIntVectorGetRs(pubKey, approxCoefficients[j])
			encryptedApproxCoefficients[j] = tmpCv
			encryptedApproxCoefficientsRs[j] = tmpRs
		}(j)
	}
	libunlynx.EndParallelize(wg)

	return encryptedApproxCoefficients, encryptedApproxCoefficientsRs
}

// AggregateApproxCoefficients aggregates the approximation coefficients of the data providers by summing the corresponding approximation
// coefficients for all indices, and this for the k different approximation degrees
func AggregateApproxCoefficients(approxCoeffs [][][]float64) [][]float64 {
	nbDataProviders := len(approxCoeffs)
	k := len(approxCoeffs[0])        // the logarithm function approximation degree
	d := len(approxCoeffs[0][0]) - 1 // the dimension of the data

	// store one array of int64 per approximation degree
	aggregatedApproxCoeffs := make([][]float64, k)
	for j := int64(0); j < int64(k); j++ {
		aggregatedApproxCoeffs[j] = make([]float64, getNumberApproxCoefficients(int64(d), j))
	}

	// sum the coefficients for all data providers
	for i := 0; i < nbDataProviders; i++ {
		// sum the coefficients for the k different approximation degrees
		for j := 0; j < k; j++ {
			nbCoeffs := len(approxCoeffs[i][j])
			for ri := 0; ri < nbCoeffs; ri++ {aggregatedApproxCoeffs[j][ri] += approxCoeffs[i][j][ri]}
		}
	}
	return aggregatedApproxCoeffs
}

// AggregateEncryptedApproxCoefficients aggregates the encrypted approximation coefficients of the data providers by summing the corresponding encrypted
// approximation coefficients for all indices, and this for the k different approximation degrees
func AggregateEncryptedApproxCoefficients(encryptedApproxCoeffs [][]*libunlynx.CipherVector) []*libunlynx.CipherVector {
	nbDataProviders := len(encryptedApproxCoeffs)

	k := 0 // the logarithm function approximation degree
	if nbDataProviders > 0 {
		// pick the smallest k among all data providers
		// (some data providers may not have answered for some higher values of k,
		// e.g. because they considered it too intrusive)
		k = len(encryptedApproxCoeffs[0])
		for i := 1; i < nbDataProviders; i++ {
			if len(encryptedApproxCoeffs[i]) < k {
				k = len(encryptedApproxCoeffs[i])
			}
		}
	}

	d := 0 // the dimension of the data
	if k > 0 {
		d = len(*encryptedApproxCoeffs[0][0]) - 1
	}

	// store one CipherVector per approximation degree
	cipherVectors := make([]*libunlynx.CipherVector, k)
	for j := 0; j < k; j++ {
		cipherVectors[j] = libunlynx.NewCipherVector(int(math.Pow(float64(d+1), float64(j+1))))
	}

	// sum the encrypted coefficients for all data providers
	for i := 0; i < nbDataProviders; i++ {
		// sum the encrypted coefficients for the k different approximation degrees
		for j := 0; j < k; j++ {
			cipherVectors[j].Add(*(cipherVectors[j]), *(encryptedApproxCoeffs[i][j]))
		}
	}

	return cipherVectors
}

// Cost computes the result of the cost function approximating the logistic regression cost function (with l2-regularization)
func Cost(weights []float64, approxCoefficients [][]float64, N int64, lambda float64) (cost float64) {
	k := int64(len(approxCoefficients))       // the logarithm function approximation degree
	d := len(approxCoefficients[0]) - 1 // the dimension of the data
	cost = 0.0

	for j := int64(0); j < k; j++ {
		// generate all indices combinations with repetitions, order matters, of size j+1 (cartesian product)
		combinations := CartesianProduct(0, int64(d+1), j+1)

		// compute the product of the weights for each combination of indices
		for row := 0; row < len(combinations); row++ {
			weightsProduct := 1.0
			combination := combinations[row]

			for i := 0; i < len(combination); i++ {weightsProduct *= weights[int(combination[i])]}
			cost += weightsProduct * float64(approxCoefficients[j][row])
		}

		cost *= PolyApproxCoefficients[j+1]
	}

	cost = (cost / float64(N)) - PolyApproxCoefficients[0]

	// l2-regularizer contribution
	// todo: check for i = 0
	regularizer := 0.0
	for i := 1; i <= d; i++ {regularizer += weights[i] * weights[i]}
	cost += (lambda / (2 * float64(N))) * regularizer
	return cost
}

// Gradient computes the gradient of the cost function approximating the logistic regression cost function
// (with l2-regularization)
func Gradient(weights []float64, approxCoeffs [][]float64, k int64, N int64, lambda float64) []float64 {

	d := len(approxCoeffs[0]) - 1 // the dimension of the data
	gradient := make([]float64, d+1)

	// compute the derivative of the cost function for all weight indices
	for idx := int64(0); idx < int64(len(gradient)); idx++ {
		derivative := make([]float64, k)

		for j := int64(0); j < k; j++ {
			// generate all indices combinations with repetitions, order matters, of size j+1 (cartesian product)
			combinations := CartesianProduct(0, int64(d+1), j+1)

			// keep track of the combinations of indices that contain index idx
			var combinationsToKeep [][]int64
			// keep track of the corresponding indices in order to index the right approx coefficient
			var indicesToKeep []int
			// keep track of the (first) index of idx in the combinations that contain index idx
			var indicesIndex []int

			nbCombinations := len(combinations)
			for row := 0; row < nbCombinations; row++ {
				combination := combinations[row]
				for i := 0; i < len(combination); i++ {
					if combination[i] == idx {
						combinationsToKeep = append(combinationsToKeep, combination)
						indicesToKeep = append(indicesToKeep, row)
						indicesIndex = append(indicesIndex, i)
						break
					}
				}
			}

			// remove index idx from these combinations (derivative of a polynomial)
			for i := 0; i < len(combinationsToKeep); i++ {
				d := indicesIndex[i]
				combinationsToKeep[i] = append(combinationsToKeep[i][:d], combinationsToKeep[i][d+1:]...)
			}

			// compute the product of the weights for each combination of indices
			for row := 0; row < len(indicesToKeep); row++ {
				weightsProduct := 1.0
				combination := combinationsToKeep[row]

				for i := 0; i < len(combination); i++ {
					weightsProduct = weightsProduct * weights[int(combination[i])]
				}

				derivative[j] += float64(count(combination, idx)+1) * weightsProduct * float64(
					approxCoeffs[j][indicesToKeep[row]])
			}
		}

		for j := int64(0); j < k; j++ {
			derivative[j] *= PolyApproxCoefficients[j+1]
		}

		for j := int64(0); j < k; j++ {
			gradient[idx] += derivative[j]
		}

		gradient[idx] /= float64(N)

		// todo: check for i = 0
		if idx >= 1 {
			gradient[idx] += (lambda / float64(N)) * weights[idx]
		}
	}

	return gradient
}

// GradientFor2 computes the gradient of the cost function approximating the logistic regression cost function for k = 2
// (with l2-regularization)
func GradientFor2(weights []float64, approxCoeffs [][]float64, k int64, N int, lambda float64) []float64 {

	d := len(approxCoeffs[0]) - 1 // the dimension of the data
	gradient := make([]float64, d+1)

	combinations := CartesianProduct(0, int64(d+1), k)

	for i := 0; i < len(weights); i++ {
		combinationsForWeight := make([][]int64, 0)
		for _, c := range combinations {
			if (c[0] == int64(i) && c[1] != int64(i)) || (c[0] != int64(i) && c[1] == int64(i)) {
				combinationsForWeight = append(combinationsForWeight, c)
			}
		}

		// k = 2
		gradient[i] = 2 * weights[i] * approxCoeffs[1][i*(d+1)+i]
		for _, c := range combinationsForWeight {
			cw := 0
			if c[0] == int64(i) {
				cw = 1
			}
			gradient[i] += weights[c[cw]] * approxCoeffs[1][c[0]*int64(d+1)+c[1]]
		}
		gradient[i] *= PolyApproxCoefficients[2]

		// k = 1
		gradient[i] += PolyApproxCoefficients[1] * float64(approxCoeffs[0][i])

		gradient[i] /= float64(N)

		// l2-regularization
		// todo: check for i = 0
		if i >= 1 {
			gradient[i] += (lambda / float64(N)) * weights[i]
		}
	}

	return gradient
}

// ComputeMinimumWeights finds the weight minimising the cost function by computing the closed form solution (only for k = 1)
func ComputeMinimumWeights(approxCoefficients [][]float64, lambda float64) []float64 {
	k := 1
	d := len(approxCoefficients[0]) - 1

	weights := make([]float64, d+1)
	for i := 0; i <= d; i++ {
		weights[i] = (-PolyApproxCoefficients[k] * float64(approxCoefficients[k-1][i])) / lambda
	}

	return weights
}

// FindMinimumWeights finds the weights minimizing the cost function using gradient descent
func FindMinimumWeights(approxCoefficients [][]float64, initialWeights []float64, N int64, lambda float64,
	step float64, maxIterations int64) []float64 {

	k := int64(len(approxCoefficients)) // the logarithm function approximation degree

	if k == 1 {return ComputeMinimumWeights(approxCoefficients, lambda)}

	//weights := initialWeights
	weights := make([]float64, len(initialWeights))
	copy(weights, initialWeights)

	minCost := math.MaxFloat64
	minWeights := make([]float64, len(weights))

	start := time.Now()
	timeout := time.Duration(60 * 3 * time.Second)
	epsilon := time.Duration(2 * time.Second)

	for iter := 0; int64(iter) < maxIterations; iter++ {
		cost := Cost(weights, approxCoefficients, N, lambda)

		//if cost >= 0.0 && cost < minCost {
		if cost >= 0.0 {
			minCost = cost
			for i := range weights {
				minWeights[i] = weights[i]
			}
		}

		gradient := Gradient(weights, approxCoefficients, k, N, lambda)
		for i := 0; i < len(weights); i++ {
			weights[i] = weights[i] - step*gradient[i]
		}

		if iter%int(float64(maxIterations)/10.0) == 0 {
			fmt.Printf("%6d cost, min. cost: %12.8f %12.8f \n", iter, cost, minCost)
		}

		t := time.Now()
		elapsed := t.Sub(start)
		if timeout-elapsed < epsilon {
			fmt.Println("elapsed:", elapsed)
			return minWeights
		}
	}

	return minWeights
}

// FindMinimumWeightsWithEncryption finds the weights minimizing the cost function using gradient descent,
// with encrypted approximation coefficients as input
func FindMinimumWeightsWithEncryption(encryptedApproxCoefficients []*libunlynx.CipherVector, privKey kyber.Scalar,
	initialWeights []float64, N int64, lambda float64, step float64, maxIterations int64, precision float64) ([]float64,
	[][]float64) {

	// the client decrypts the encrypted approximation coefficients
	approxCoefficients := make([][]float64, len(encryptedApproxCoefficients))
	for i := range encryptedApproxCoefficients {
		approxCoefficients[i] = Int64ToFloat641DArray(libunlynx.DecryptIntVectorWithNeg(privKey,
			encryptedApproxCoefficients[i]))

		// rescale the approximation coefficients
		for j := range approxCoefficients[i] {
			approxCoefficients[i][j] /= precision
		}
	}

	// the client then computes the weights in clear
	weights := FindMinimumWeights(approxCoefficients, initialWeights, N, lambda, step, maxIterations)

	return weights, approxCoefficients
}

// LogisticRegressionCost computes the result of the logistic regression cost function (with l2-regularization)
func LogisticRegressionCost(weights []float64, x [][]float64, y []int64, N int64, lambda float64) float64 {
	cost := 0.0

	for i := 0; i < len(x); i++ {
		s1 := 0.0
		for j := 0; j < len(weights); j++ {
			s1 += x[i][j] * weights[j]
		}
		s2 := float64(y[i]) * s1
		s1 = math.Log(1 + math.Exp(s1))
		cost += s1 - s2
	}

	// l2-regularizer contribution
	s3 := 0.0
	for i := 0; i < len(weights); i++ {
		s3 += weights[i] * weights[i]
	}
	s3 *= lambda / 2 * float64(N)
	cost += s3

	return cost
}

// LogisticRegressionGradient compute the gradient of the logisitic regression cost function (with l2-regularization)
func LogisticRegressionGradient(weights []float64, X [][]float64, y []float64, N int, lambda float64) []float64 {
	gradient := make([]float64, len(weights))

	for idx := 0; idx < len(weights); idx++ {
		s1 := 0.0
		for i := 0; i < len(X); i++ {
			s2 := 0.0
			for j := 0; j < len(weights); j++ {
				s2 += X[i][j] * weights[j]
			}
			s1 += X[i][idx] * (sigmoid(s2) - y[i])
		}
		gradient[idx] = s1

		// l2-regularizer contribution to the derivative
		gradient[idx] += (lambda / float64(N)) * weights[idx]
	}

	return gradient
}

// the sigmoid function
func sigmoid(x float64) float64 {
	return math.Exp(x) / (1 + math.Exp(x))
}

// PredictInClear computes a prediction according to logistic regression for data and weights given in clear
func PredictInClear(data []float64, weights []float64) float64 {
	sum := 0.0
	for i := 0; i < len(data); i++ {
		sum += weights[i+1] * data[i]
	}

	prediction := 1 / (1 + math.Exp(-weights[0]-sum))

	return prediction
}

// Predict computes a prediction according to logistic regression for encrypted data and weights in clear
func Predict(encryptedData libunlynx.CipherVector, weights []float64, privKey kyber.Scalar, precisionWeights float64,
	precisionData float64) float64 {
	// convert float64 weights to int64 weights

	weightsAsInt := make([]int64, len(weights))
	for i := 0; i < len(weights); i++ {
		weightsAsInt[i] = int64(math.Round(precisionWeights * weights[i]))
	}

	// compute the sum of the encrypted data with integer weights
	encryptedSum := libunlynx.NewCipherText()

	for i := 0; i < len(encryptedData); i++ {
		// add weights[i+1] times the encrypted data[i]
		if weightsAsInt[i+1] >= 0 {
			for j := 0; j < int(weightsAsInt[i+1]); j++ {
				encryptedSum.Add(*encryptedSum, encryptedData[i])
			}
		} else {
			for j := 0; j < -int(weightsAsInt[i+1]); j++ {
				encryptedSum.Sub(*encryptedSum, encryptedData[i])
			}
		}
	}

	// decrypt the encrypted sum value and compute the prediction as is customary
	sum := float64(libunlynx.DecryptIntWithNeg(privKey, *encryptedSum))
	sum /= precisionWeights * precisionData

	prediction := 1 / (1 + math.Exp(-weights[0]-sum))

	return prediction
}

// PredictHomomorphic computes a prediction according to logistic regression for encrypted data and weights in clear,
// using homomorphic encryption
func PredictHomomorphic(encryptedData libunlynx.CipherVector, weights []float64, privKey kyber.Scalar,
	precisionWeights float64, precisionData float64) float64 {
	// multiplication by a floating point number is not supported by ElGamal,
	// so multiply the floating point weights by a precision factor before rounding them to integers;
	// divide the result by the same precision factor at the end

	// compute the sum of the encrypted data with integer weights
	encryptedSum := libunlynx.NewCipherText()

	for i := 0; i < len(encryptedData); i++ {
		scalar := libunlynx.SuiTe.Scalar().One()
		scalar = kyber.Scalar.SetInt64(scalar, int64(precisionWeights*math.Abs(weights[i+1])))

		ct := encryptedData[i]
		ct.MulCipherTextbyScalar(ct, scalar)

		if weights[i+1] >= 0 {
			encryptedSum.Add(*encryptedSum, ct)
		} else {
			encryptedSum.Sub(*encryptedSum, ct)
		}
	}

	// decrypt the encrypted sum value and compute the prediction as is customary
	sum := float64(libunlynx.DecryptIntWithNeg(privKey, *encryptedSum))
	sum /= precisionWeights * precisionData

	prediction := 1 / (1 + math.Exp(-weights[0]-sum))

	return prediction
}

//--------------------
// Data pre-processing
//--------------------

// ComputeMeans returns the means of each column of the given data matrix
func ComputeMeans(data [][]float64) []float64 {
	nbFeatures := len(data[0])

	means := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(data, i)
		means[i], _ = stats.Mean(feature)
	}

	return means
}

// ComputeStandardDeviations returns the standard deviation of each column of the given data matrix
func ComputeStandardDeviations(data [][]float64) []float64 {
	nbFeatures := len(data[0])

	standardDeviations := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(data, i)
		standardDeviations[i], _ = stats.StandardDeviation(feature)
	}

	return standardDeviations
}

// Standardise returns the standardized 2D array version of the given 2D array
// i.e. x' = (x - mean) / standard deviation
func Standardise(matrix [][]float64) [][]float64 {

	nbFeatures := len(matrix[0])

	sds := make([]float64, nbFeatures)
	means := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(matrix, i)
		means[i], _ = stats.Mean(feature)
		sds[i], _ = stats.StandardDeviation(feature)
	}

	standardisedMatrix := make([][]float64, len(matrix))
	for record := 0; record < len(matrix); record++ {
		standardisedMatrix[record] = make([]float64, nbFeatures)
		for i := 0; i < nbFeatures; i++ {
			standardisedMatrix[record][i] = float64(matrix[record][i]-means[i]) / sds[i]
		}
	}

	return standardisedMatrix
}

// StandardiseWithTrain standardises a matrix with the given matrix means and standard deviations
func StandardiseWithTrain(matrixTest, matrixTrain [][]float64) [][]float64 {

	nbFeatures := len(matrixTest[0])

	sd := make([]float64, nbFeatures)
	mean := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(matrixTrain, i)

		mean[i], _ = stats.Mean(feature)
		sd[i], _ = stats.StandardDeviation(feature)
	}

	standardisedMatrix := make([][]float64, len(matrixTest))
	for record := 0; record < len(matrixTest); record++ {
		standardisedMatrix[record] = make([]float64, nbFeatures)
		for i := 0; i < nbFeatures; i++ {
			standardisedMatrix[record][i] = float64(matrixTest[record][i]-mean[i]) / sd[i]
		}
	}

	return standardisedMatrix
}

// StandardiseWith standardises a dataset column-wise using the given means and standard deviations
func StandardiseWith(data [][]float64, means []float64, standardDeviations []float64) [][]float64 {

	nbFeatures := len(data[0])

	standardisedData := make([][]float64, len(data))
	for record := 0; record < len(data); record++ {
		standardisedData[record] = make([]float64, nbFeatures)
		for i := 0; i < nbFeatures; i++ {
			standardisedData[record][i] = float64(data[record][i]-means[i]) / standardDeviations[i]
		}
	}

	return standardisedData
}

// Normalize normalises a matrix column-wise
func Normalize(matrix [][]float64) [][]float64 {

	nbFeatures := len(matrix[0])
	min := make([]float64, nbFeatures)
	max := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(matrix, i)

		min[i], _ = stats.Min(feature)
		max[i], _ = stats.Max(feature)
	}

	normalizedMatrix := make([][]float64, len(matrix))
	for record := 0; record < len(matrix); record++ {
		normalizedMatrix[record] = make([]float64, nbFeatures)
		for i := 0; i < nbFeatures; i++ {
			normalizedMatrix[record][i] = float64(matrix[record][i]-min[i]) / (max[i] - min[i])
		}
	}

	return normalizedMatrix
}

// NormalizeWith normalises a matrix column-wise with the given matrix min and max values
func NormalizeWith(matrixTest, matrixTrain [][]float64) [][]float64 {

	nbFeatures := len(matrixTest[0])
	min := make([]float64, nbFeatures)
	max := make([]float64, nbFeatures)

	for i := int64(0); i < int64(nbFeatures); i++ {
		feature := GetColumn(matrixTrain, i)

		min[i], _ = stats.Min(feature)
		max[i], _ = stats.Max(feature)
	}

	normalizedMatrix := make([][]float64, len(matrixTest))
	for record := 0; record < len(matrixTest); record++ {
		normalizedMatrix[record] = make([]float64, nbFeatures)
		for i := 0; i < nbFeatures; i++ {
			normalizedMatrix[record][i] = float64(matrixTest[record][i]-min[i]) / (max[i] - min[i])
		}
	}

	return normalizedMatrix
}

// Augment returns the given 2D array with an additional all 1's column prepended as the first column
func Augment(matrix [][]float64) [][]float64 {
	column := make([]float64, len(matrix))
	for i := 0; i < len(matrix); i++ {
		column[i] = 1
	}

	matrix = InsertColumn(matrix, column, 0)

	return matrix
}

// returns the given 2D array flattened into a 1D array
func flatten(matrix [][]float64) []float64 {
	var array []float64
	for i := range matrix {
		array = append(array, matrix[i]...)
	}

	return array
}

// InsertColumn returns a new 2D array with the column <column> inserted into the given 2D array <matrix> at index <idx>
func InsertColumn(matrix [][]float64, column []float64, idx int) [][]float64 {
	newMatrix := make([][]float64, len(matrix))
	for i := range matrix {
		//newMatrix[i] = make([]float64, len(matrix[i]))
		copy(newMatrix[i], matrix[i][0:idx])
		newMatrix[i] = append(newMatrix[i], column[i])
		newMatrix[i] = append(newMatrix[i], matrix[i][idx:]...)
		//newMatrix[i] = append([]float64{column[i]}, newMatrix[i]...)
	}

	return newMatrix
}

// ----------------------
// Performance evaluation
// ----------------------

// returns the number of true positives in the prediction
func truePositive(predicted []int64, actual []int64) int {
	count := 0
	for i := range predicted {if predicted[i] == 1 && actual[i] == 1 {count++}}
	return count
}

// returns the number of true negatives in the prediction
func trueNegative(predicted []int64, actual []int64) int {
	count := 0
	for i := range predicted {if predicted[i] == 0 && actual[i] == 0 {count++}}
	return count
}

// returns the number of false positive in the prediction
func falsePositive(predicted []int64, actual []int64) int {
	count := 0
	for i := range predicted {if predicted[i] == 1 && actual[i] == 0 {count++}}
	return count
}

// returns the number of false negatives in the prediction
func falseNegative(predicted []int64, actual []int64) int {
	count := 0
	for i := range predicted {if predicted[i] == 0 && actual[i] == 1 {count++}}
	return count
}

// Accuracy computes the accuracy of the prediction
// i.e. Accuracy = (TP + TN) / (TP + FP + FN + TN)
func Accuracy(predicted []int64, actual []int64) float64 {
	return float64(truePositive(predicted, actual)+trueNegative(predicted, actual)) / float64(len(actual))
}

// Precision computes the precision of the prediction
// i.e. Precision = TP / (TP + FP)
func Precision(predicted []int64, actual []int64) float64 {
	return float64(truePositive(predicted, actual)) / float64(truePositive(predicted, actual)+falsePositive(predicted, actual))
}

// Recall computes the recall of the prediction
// i.e. Recall = TP / (TP + FN)
func Recall(predicted []int64, actual []int64) float64 {
	return float64(truePositive(predicted, actual)) / float64(truePositive(predicted, actual)+falseNegative(predicted, actual))
}

// Fscore computes the F-score of the prediction
// i.e. F-score = (2 * Precision * Recall) / (Precision + Recall)
func Fscore(predicted []int64, actual []int64) float64 {
	return float64(2*Precision(predicted, actual)*Recall(predicted, actual)) / float64(Precision(predicted,
		actual)+Recall(predicted, actual))
}

// ComputeTPRFPR computes the True Positive Rate and False Positive Rate given the predictions and the true values
func ComputeTPRFPR(predicted []float64, actual []int64) ([]float64, []float64) {
	// Note: (https://godoc.org/github.com/gonum/stat#ROC)
	// "For a given cutoff value, observations corresponding to entries in y greater than the cutoff value are
	// classified as false, while those below (or equal to) the cutoff value are classified as true.
	// These assigned class labels are compared with the true values in the classes slice and used to calculate the
	// FPR and TPR."

	// convert the 0/1 labels to true/false labels
	labels := make([]bool, len(actual))
	for i := 0; i < len(actual); i++ {if actual[i] == 0 {labels[i] = true}}

	// sort the predicted values in increasing order together with their true labels (ROC() function requirement)
	sortedPredictions := make([]float64, len(predicted))
	copy(sortedPredictions, predicted)
	stat.SortWeightedLabeled(sortedPredictions, labels, nil)

	// compute TPR and FPR for varying thresholds
	tpr, fpr := stat.ROC(0, sortedPredictions, labels, nil)

	return tpr, fpr
}

// AreaUnderCurve computes the AUC (Area Under the Curve) for the predicted values
func AreaUnderCurve(predicted []float64, actual []int64) float64 {
	// compute the TPR (True Positive Rate) and FPR (False Positive Rate)
	tpr, fpr := ComputeTPRFPR(predicted, actual)
	// compute the Area Under Curve (AUC)
	auc := integrate.Trapezoidal(fpr, tpr)
	return auc
}

/*func PlotROC(predicted []float64, actual []int64) {
	// compute the TPR (True Positive Rate) and FPR (False Positive Rate)
	tpr, fpr := ComputeTPRFPR(predicted, actual)

	p, err := plot.New()
	if err != nil {
		panic(err)
	}

	p.Title.Text = "ROC curve"
	p.X.Label.Text = "False Positive Rate"
	p.Y.Label.Text = "True Positive Rate"

	dataPoints := make(plotter.XYs, len(tpr))
	for i := range dataPoints {
		dataPoints[i].X = fpr[i]
		dataPoints[i].Y = tpr[i]
	}

	l, err := plotter.NewLine(dataPoints)
	if err != nil {
		panic(err)
	}
	l.LineStyle.Color = color.RGBA{R: 0, B: 228, G: 110, A: 255}

	p.Add(l)
	p.Legend.Add("ROC curve", l)

	// Save the plot to a PNG file
	if err := p.Save(4*vg.Inch, 4*vg.Inch, "../../data/ROC_curve.png"); err != nil {
		panic(err)
	}
}*/

// SaveToFile saves a float64 array to file
func SaveToFile(array []float64, filename string) {
	file, err := os.OpenFile(filename, os.O_APPEND, 0666)

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	for j := 0; j < len(array)-1; j++ {
		_, err = file.WriteString(fmt.Sprint(array[j]) + ",")
	}
	_, err = file.WriteString(fmt.Sprintln(array[len(array)-1]))

	file.Close()
}

// PrintForLatex for copy-pasting in LaTex
func PrintForLatex(accuracy, precision, recall, fscore, auc float64) {
	fmt.Println("Latex:")
	fmt.Printf("%.2f\\%% & %.2f\\%% & %.2f\\%% & %.6f & %.6f \\\\\n",
		accuracy*100, precision*100, recall*100, fscore, auc)
}

//----------------------------
// Loading an external dataset
//----------------------------

// String2DToFloat64 converts a 2D string matrix into a 2D float64 matrix
func String2DToFloat64(dataString [][]string) [][]float64 {

	nbFeatures := 0
	nbRecordsIgnored := 0

	var dataFloat64 [][]float64
	for idx, line := range dataString {
		var array []float64
		for _, e := range line {
			i, err := strconv.ParseFloat(strings.TrimSpace(e), 64)

			if err == nil {
				nbFeatures = len(line)
			}

			if err != nil {
				log.LLvl1("Incorrect record formatting: record", idx, "will be ignored")
				log.LLvl1("Cause:", err)
				nbRecordsIgnored++
				break
			}
			array = append(array, i)
		}
		dataFloat64 = append(dataFloat64, array)
	}

	// remove the incorrectly formatted records
	var data [][]float64
	for _, row := range dataFloat64 {
		if len(row) == nbFeatures {
			data = append(data, row)
		}
	}

	log.LLvl2("Total number of records ignored:", nbRecordsIgnored)

	return data
}

// LoadData loads some specific datasets from file into a pair of feature matrix and label vector
// the available datasets are: SPECTF, Pima, PCS and LBW
func LoadData(dataset string, filename string) ([][]float64, []int64) {

	var data [][]float64
	var X [][]float64
	var y []int64

	labelColumn := int64(0)

	switch dataset {
	case "CSV":
		dataString := ReadFile(filename, ",")
		data = String2DToFloat64(dataString)
		//labelColumn = int64(0)
		X = RemoveColumn(data, int64(len(data[0])-1))
		y = Float64ToInt641DArray(GetColumn(data, labelColumn))
	case "SPECTF":
		dataString := ReadFile(filename, ",")
		data = String2DToFloat64(dataString)
		labelColumn = int64(0)

		X = RemoveColumn(data, labelColumn)
		y = Float64ToInt641DArray(GetColumn(data, labelColumn))
	case "Pima":
		dataString := ReadFile(filename, ",")
		data = String2DToFloat64(dataString)

		labelColumn = int64(8)
		X = RemoveColumn(data, labelColumn)
		y = Float64ToInt641DArray(GetColumn(data, labelColumn))
	case "PCS":
		dataString := ReadFile(filename, ",")
		// remove the index column and the two last columns (unused)
		dataString = RemoveColumnString(dataString, 11)
		dataString = RemoveColumnString(dataString, 10)
		dataString = RemoveColumnString(dataString, 0)

		// convert all fields from string to float64
		data = String2DToFloat64(dataString)

		X = RemoveColumn(data, 0)
		y = Float64ToInt641DArray(GetColumn(data, 0))
	case "LBW":
		dataString := ReadFile(filename, " ")

		// replace FTV column "2+" occurrences by 2
		dataString = ReplaceString(dataString, "\"2+\"", "2")

		// convert all fields from string to float64
		data = String2DToFloat64(dataString)

		// remove the index column
		data = RemoveColumn(data, 3)
		// remove the actual birth weight column (the classification task becomes trivial otherwise)
		data = RemoveColumn(data, 1)

		labelColumn := int64(2)
		X = RemoveColumn(data, labelColumn)
		y = Float64ToInt641DArray(GetColumn(data, labelColumn))
	default:
		dataString := ReadFile(filename, ",")
		data = String2DToFloat64(dataString)
		X = RemoveColumn(data, 0)
		y = Float64ToInt641DArray(GetColumn(data, 0))
	}

	return X, y
}

// ReadFile reads a dataset from file into a string matrix
// removes incorrectly formatted records
func ReadFile(path string, separator string) [][]string {
	inFile, err := os.Open(path)

	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	var matrix [][]string
	nbrRecordsIgnored := 0

	for scanner.Scan() {
		line := strings.Split(scanner.Text(), separator)
		var array []string
		for _, e := range line {
			i := strings.TrimSpace(e)
			if i != "" {
				array = append(array, i)
			}
		}
		matrix = append(matrix, array)
	}

	// remove incorrectly formatted records
	// todo: take max of len of all rows
	nbrFeatures := len(matrix[0])
	var result [][]string
	for _, row := range matrix {
		if len(row) == nbrFeatures {
			result = append(result, row)
		} else {
			log.LLvl1("Incorrect record formatting: record", row, "will be ignored")
			nbrRecordsIgnored++
		}
	}

	log.LLvl2("Total number of records ignored:", nbrRecordsIgnored)

	return result
}

// GetColumn returns the column at index <idx> in the given 2D array <matrix>
func GetColumn(matrix [][]float64, idx int64) []float64 {

	if len(matrix) < 0 {
		log.Fatalf("error: empty matrix")
		os.Exit(2)
	}

	if idx >= int64(len(matrix[0])) {
		log.Fatalf("error: column index exceeds matrix dimension")
		os.Exit(2)
	}

	array := make([]float64, len(matrix))
	for i := range matrix {
		array[i] = matrix[i][idx]
	}

	return array
}

// RemoveColumn returns a 2D array with the column at index <idx> removed from the given 2D array <matrix>
func RemoveColumn(matrix [][]float64, idx int64) [][]float64 {
	if idx >= int64(len(matrix)) {
		log.Fatalf("error: column index exceeds matrix dimension")
		os.Exit(2)
	}

	truncatedMatrix := make([][]float64, len(matrix))
	for i := range matrix {
		//truncatedMatrix[i] = make([]float64, len(matrix[i]) - 1)
		truncatedMatrix[i] = append(truncatedMatrix[i], matrix[i][:idx]...)
		truncatedMatrix[i] = append(truncatedMatrix[i], matrix[i][idx+1:]...)
	}

	return truncatedMatrix
}

// RemoveColumnString removes the column at index <idx> of the given string matrix
func RemoveColumnString(matrix [][]string, idx int) [][]string {
	if idx >= len(matrix) {
		log.Fatalf("error: column index exceeds matrix dimension")
		os.Exit(2)
	}

	truncatedMatrix := make([][]string, len(matrix))
	for i := range matrix {
		//truncatedMatrix[i] = make([]float64, len(matrix[i]) - 1)
		truncatedMatrix[i] = append(truncatedMatrix[i], matrix[i][:idx]...)
		truncatedMatrix[i] = append(truncatedMatrix[i], matrix[i][idx+1:]...)
	}

	return truncatedMatrix
}

// ReplaceString replaces all strings <old> by string <new> in the given string matrix
func ReplaceString(matrix [][]string, old string, new string) [][]string {
	for i := 0; i < len(matrix); i++ {
		for j := 0; j < len(matrix[i]); j++ {if matrix[i][j] == old {matrix[i][j] = new}}
	}
	return matrix
}

// PartitionDataset partitions a dataset with feature matrix X and label vector y into two datasets according to the given ratio
// optionally shuffles the dataset before partition
func PartitionDataset(X [][]float64, y []int64, ratio float64, shuffle bool, seed int64) ([][]float64, []int64,
	[][]float64, []int64) {

	var XTrain [][]float64
	var yTrain []int64
	var XTest [][]float64
	var yTest []int64

	numRecords := len(X)
	numRecordsTrain := int(float64(numRecords) * ratio)

	indices := Range(0, int64(numRecords))

	if shuffle {
		rand.Seed(seed)
		rand.Shuffle(len(indices), func(i, j int) { indices[i], indices[j] = indices[j], indices[i] })
	}

	indicesTrain := indices[0:numRecordsTrain]
	indicesTest := indices[numRecordsTrain:]

	for i := 0; i < len(indicesTrain); i++ {
		XTrain = append(XTrain, X[indicesTrain[i]])
		yTrain = append(yTrain, y[indicesTrain[i]])
	}

	for i := 0; i < len(indicesTest); i++ {
		XTest = append(XTest, X[indicesTest[i]])
		yTest = append(yTest, y[indicesTest[i]])
	}

	return XTrain, yTrain, XTest, yTest
}

//Partition the dataset while doing cross validation
func PartitionDatasetCV(X [][]float64, y []int64, partition int64, kfold int64) ([][]float64, []int64, [][]float64, []int64) {
	var XTrain [][]float64
	var yTrain []int64
	var XTest [][]float64
	var yTest []int64

	numRecords := int64(len(X))
	numRecordsTest := int64(numRecords) / kfold
	indicesTest := Range(partition * numRecordsTest, (partition+1) * numRecordsTest)
	indicesTrain := append(Range(0, partition * numRecordsTest), Range((partition+1) * numRecordsTest, numRecords)...)

	for i := 0; i < len(indicesTrain); i++ {
		XTrain = append(XTrain, X[indicesTrain[i]])
		yTrain = append(yTrain, y[indicesTrain[i]])
	}

	for i := 0; i < len(indicesTest); i++ {
		XTest = append(XTest, X[indicesTest[i]])
		yTest = append(yTest, y[indicesTest[i]])
	}

	return XTrain, yTrain, XTest, yTest
}

// GetDataForDataProvider returns data records from a file for a given data provider based on its id
func GetDataForDataProvider(filename string, dataProviderIdentity network.ServerIdentity, NbrDps int64) [][]float64 {
	var dataForDP [][]float64
	data := String2DToFloat64(ReadFile(filename, ","))
	dataProviderID := dataProviderIdentity.String()
	dpID, err := strconv.Atoi(dataProviderID[len(dataProviderID)-2 : len(dataProviderID)-1])

	if err == nil {
		for i := int64(0); i < int64(len(data)); i++ {
			if i % NbrDps == int64(dpID) {dataForDP = append(dataForDP, data[i])}
		}
		fmt.Println("DP", dpID, " has:", len(dataForDP), "records")
	}

	return dataForDP
}


// GetDataForDataProvider returns data records from a file for a given data provider based on its id
func GetDataForDataProviderWithoutSplitting (filename string, dataProviderIdentity network.ServerIdentity) [][]float64 {
	var dpData [][]float64
	dataProviderID := dataProviderIdentity.String()
	dpID, err := strconv.Atoi(dataProviderID[len(dataProviderID)-2 : len(dataProviderID)-1])

	if err == nil {
		dpData = String2DToFloat64(ReadFile(filename + "_" + strconv.Itoa(dpID) + ".csv", ","))
		fmt.Println("DP", dpID, " has:", len(dpData), "records")
	}
	return dpData
}

// -----------------
// Utility functions
// -----------------

// Range returns the integer range going from <start> (included) to <end> (excluded)
func Range(start int64, end int64) []int64 {
	n := end - start
	result := make([]int64, n)
	for i := int64(0); i < n; i++ {
		result[i] = start + i
	}
	return result
}

// CartesianProduct returns the cartesian product of <dimension> arrays ranging from <start> (included) to <end> (excluded)
func CartesianProduct(start, end int64, dimension int64) [][]int64 {
	// generate all indices combinations with repetitions, order matters, of size j+1 (cartesian product)
	indices := make([][]int64, dimension)
	for i := int64(0); i < dimension; i++ {
		indices[i] = Range(start, end)
	}
	combinationsMatrix := combin.Cartesian(nil, Int64ToFloat642DArray(indices))

	// convert the cartesian product dense matrix into a 2D slice
	// note: dimension == nbCols
	nbRows, _ := combinationsMatrix.Dims()
	combinations := make([][]int64, nbRows)
	for i := 0; i < nbRows; i++ {
		combinations[i] = make([]int64, dimension)
		for j := 0; int64(j) < dimension; j++ {
			combinations[i][j] = int64(combinationsMatrix.At(i, j))
		}
	}

	return combinations
}

// returns the number of occurrences of <element> in <array> for int64
func count(array []int64, element int64) int {
	count := 0
	for _, e := range array {
		if e == element {
			count++
		}
	}
	return count
}

//-----------
// Conversion
//-----------

// Int64ToFloat641DArray converts a one-dimensional int64 array to a one-dimensional float64 array
func Int64ToFloat641DArray(arrayInt64 []int64) []float64 {
	k := len(arrayInt64)

	arrayFloat64 := make([]float64, k)
	for i := 0; i < k; i++ {
		arrayFloat64[i] = float64(arrayInt64[i])
	}

	return arrayFloat64
}

// Float64ToInt641DArray converts a one-dimensional int64 array to a one-dimensional float64 array
func Float64ToInt641DArray(arrayFloat64 []float64) []int64 {
	k := len(arrayFloat64)

	arrayInt64 := make([]int64, k)
	for i := 0; i < k; i++ {
		arrayInt64[i] = int64(math.Round(arrayFloat64[i]))
	}

	return arrayInt64
}

// Int64ToFloat642DArray converts a two-dimensional int64 array to a two-dimensional float64 array
func Int64ToFloat642DArray(arrayInt64 [][]int64) [][]float64 {
	k := len(arrayInt64)

	arrayFloat64 := make([][]float64, k)
	for i := 0; i < k; i++ {
		arrayFloat64[i] = Int64ToFloat641DArray(arrayInt64[i])
	}

	return arrayFloat64
}

// Float64ToInt642DArray converts a two-dimensional int64 array to a two-dimensional float64 array
func Float64ToInt642DArray(arrayFloat64 [][]float64) [][]int64 {
	k := len(arrayFloat64)

	arrayInt64 := make([][]int64, k)
	for i := 0; i < k; i++ {
		arrayInt64[i] = Float64ToInt641DArray(arrayFloat64[i])
	}

	return arrayInt64
}

// Float64ToInt641DArrayWithPrecision converts a 1D float64 array to a 1D int64 array with the given precision
func Float64ToInt641DArrayWithPrecision(arrayFloat64 []float64, precision float64) []int64 {
	k := len(arrayFloat64)

	arrayInt64 := make([]int64, k)
	for i := 0; i < k; i++ {
		arrayInt64[i] = int64(math.Round(arrayFloat64[i] * precision))
	}

	return arrayInt64
}

// Float64ToInt642DArrayWithPrecision converts a 2D float64 array to a 2D int64 array with the given precision
func Float64ToInt642DArrayWithPrecision(arrayFloat64 [][]float64, precision float64) [][]int64 {
	k := len(arrayFloat64)

	arrayInt64 := make([][]int64, k)
	for i := 0; i < k; i++ {
		arrayInt64[i] = Float64ToInt641DArrayWithPrecision(arrayFloat64[i], precision)
	}

	return arrayInt64
}

// Round rounds a float number to the nearest <unit> digits
func Round(x, unit float64) float64 {
	return math.Round(x/unit) * unit
}
