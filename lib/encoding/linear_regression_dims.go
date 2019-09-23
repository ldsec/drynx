package libdrynxencoding

import (
	"fmt"
	"github.com/alex-ant/gomath/gaussian-elimination"
	"github.com/alex-ant/gomath/rational"
	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/range"
	"github.com/ldsec/unlynx/lib"
	"github.com/tonestuff/quadratic"
	"go.dedis.ch/kyber/v3"
	"math"
	"time"
)

//EncodeLinearRegressionDims implements a d-dimensional linear regression algorithm on the query results
func EncodeLinearRegressionDims(input1 [][]int64, input2 []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeLinearRegressionDimsWithProofs(input1, input2, pubKey, nil, nil)
	return resultEnc, resultClear
}

//EncodeLinearRegressionDimsWithProofs implements a d-dimensional linear regression algorithm on the query results with range proofs
func EncodeLinearRegressionDimsWithProofs(input1 [][]int64, input2 []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynxrange.CreateProof) {
	//sum the Xs and their squares, the Ys and the product of every pair of X and Y
	sumXj := int64(0)
	sumY := int64(0)
	sumXjY := int64(0)
	sumXjX := int64(0)

	//Input dimension
	d := len(input1[0])
	//Input number of Samples
	N := len(input1)

	var plaintextValues []int64
	var r []kyber.Scalar

	var CiphertextTuple []libunlynx.CipherText
	//Encrypt the number of data records considered
	NEncrypted, r0 := libunlynx.EncryptIntGetR(pubKey, int64(N))
	CiphertextTuple = append(CiphertextTuple, *NEncrypted)
	plaintextValues = append(plaintextValues, int64(N))
	r = append(r, r0)

	var StoredVals []int64

	//loop over dimensions
	for j := 0; j < d; j++ {
		sumXj = int64(0)
		sumXjY = int64(0)
		for i := 0; i < N; i++ {
			x := input1[i][j]
			sumXj += x
			sumXjY += input2[i] * x
		}
		sumXjEncrypted, rTemp := libunlynx.EncryptIntGetR(pubKey, sumXj)
		CiphertextTuple = append(CiphertextTuple, *sumXjEncrypted)
		plaintextValues = append(plaintextValues, sumXj)
		r = append(r, rTemp)
		StoredVals = append(StoredVals, sumXjY)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sumXjX = int64(0)
			for i := 0; i < N; i++ {
				sumXjX += input1[i][j] * input1[i][k]
			}
			sumXjXkEncrypted, rTemp := libunlynx.EncryptIntGetR(pubKey, sumXjX)
			CiphertextTuple = append(CiphertextTuple, *sumXjXkEncrypted)
			plaintextValues = append(plaintextValues, sumXjX)
			r = append(r, rTemp)
		}
	}

	for _, el := range input2 {
		sumY += el
	}
	sumYEncrypted, ry := libunlynx.EncryptIntGetR(pubKey, sumY)
	CiphertextTuple = append(CiphertextTuple, *sumYEncrypted)
	plaintextValues = append(plaintextValues, sumY)
	r = append(r, ry)

	for j := 0; j < len(StoredVals); j++ {
		sumXjYEncrypted, rTemp := libunlynx.EncryptIntGetR(pubKey, StoredVals[j])
		CiphertextTuple = append(CiphertextTuple, *sumXjYEncrypted)
		plaintextValues = append(plaintextValues, StoredVals[j])
		r = append(r, rTemp)
	}

	if sigs == nil {
		return CiphertextTuple, []int64{0}, nil
	}
	//input range validation proof
	createProofs := make([]libdrynxrange.CreateProof, len(plaintextValues))
	wg := libunlynx.StartParallelize(len(plaintextValues))
	for i, v := range plaintextValues {
		go func(i int, v int64) {
			defer wg.Done()
			//input range validation proof
			createProofs[i] = libdrynxrange.CreateProof{Sigs: libdrynxrange.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: CiphertextTuple[i]}
		}(i, v)
	}
	libunlynx.EndParallelize(wg)
	return CiphertextTuple, []int64{0}, createProofs
}

//DecodeLinearRegressionDims implements a d-dimensional linear regression algorithm, in this encoding, we assume the system to have a perfect solution
//TODO least-square computation and not equality
func DecodeLinearRegressionDims(result []libunlynx.CipherText, secKey kyber.Scalar) []float64 {
	//get the the number of dimensions by solving the equation: d^2 + 5d + 4 = 2*len(result)
	posSol, _ := quadratic.Solve(1, 5, complex128(complex(float32(4-2*len(result)), 0)))
	d := int(real(posSol))

	matrixAugmented := make([][]int64, d+1, d+2)
	for i := range matrixAugmented {
		matrixAugmented[i] = make([]int64, d+2)
	}

	//Build the augmented matrix
	s := 0
	l := d + 1
	k := d + 1
	i := 0
	for j := 0; j < len(result)-d-1; j++ {
		if j == l {
			k--
			l = l + k
			i++
			s = 0
		}
		matrixAugmented[i][i+s] = libunlynx.DecryptIntWithNeg(secKey, result[j])
		if i != i+s {
			matrixAugmented[i+s][i] = libunlynx.DecryptIntWithNeg(secKey, result[j])
		}
		s++
	}

	for j := len(result) - d - 1; j < len(result); j++ {
		matrixAugmented[j-len(result)+d+1][d+1] = libunlynx.DecryptIntWithNeg(secKey, result[j])
	}

	matrixRational := make([][]rational.Rational, d+1, d+2)
	for i := range matrixAugmented {
		matrixRational[i] = make([]rational.Rational, d+2)
	}
	for i := range matrixAugmented {
		for j := 0; j < d+2; j++ {
			matrixRational[i][j] = rational.New(matrixAugmented[i][j], 1)
		}
	}

	//Solve the linear system of equations and return x = [c0, c1, c2, ..., cd]
	var solution [][]rational.Rational
	solution, _ = gaussian.SolveGaussian(matrixRational, false)

	coeffs := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffs[i] = solution[i][0].Float64()
	}
	return coeffs
}

func h(weights []float64, x []float64) float64 {
	h := weights[0]
	for i := 0; i < len(x); i++ {
		h += weights[i+1] * x[i]
	}
	return h
}

// CostLinearRegression implements the cost function for the linear regression [TEST]
func CostLinearRegression(weights []float64, X [][]float64, y []float64) float64 {
	m := len(X)

	cost := float64(1 / (2 * m))
	sum := float64(0)
	for i, sample := range X {
		sum += math.Pow(h(weights, sample)-y[i], 2)
	}
	return cost * sum
}

// GradientLinearRegression implements the gradient descent algorithm for the linear regression [TEST]
func GradientLinearRegression(weights []float64, X [][]float64, y []float64, lambda float64) []float64 {
	dim := len(X[0])
	m := float64(len(X))
	gradients := make([]float64, dim)

	for i := 0; i < dim; i++ {
		gradientI := float64(0)
		for j, sample := range X {
			if i == 0 {
				gradientI += h(weights, sample) - y[j]
			} else {
				gradientI += (h(weights, sample) - y[j]) * sample[j]
			}
		}
		gradientI = gradientI * lambda / m
		gradients[i] = gradientI
	}
	return gradients
}

// FindMinimumWeightsLinearRegression runs a linear regression (to find the mininum weigths) [TEST]
func FindMinimumWeightsLinearRegression(initialWeights []float64, X [][]float64, y []float64, lambda float64, maxIterations int) []float64 {

	//weights := initialWeights
	weights := make([]float64, len(initialWeights))
	copy(weights, initialWeights)

	minCost := math.MaxFloat64
	minWeights := make([]float64, len(weights))

	start := time.Now()
	timeout := time.Duration(60 * 3 * time.Second)
	epsilon := time.Duration(2 * time.Second)

	for iter := 0; iter < maxIterations; iter++ {
		cost := CostLinearRegression(weights, X, y)

		if cost >= 0.0 {
			minCost = cost
			for i := range weights {
				minWeights[i] = weights[i]
			}
		}

		gradient := GradientLinearRegression(weights, X, y, lambda)
		for i := 0; i < len(weights); i++ {
			weights[i] = weights[i] - lambda*gradient[i]
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
