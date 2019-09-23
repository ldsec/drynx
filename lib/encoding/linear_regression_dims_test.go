package libdrynxencoding_test

import (
	"github.com/alex-ant/gomath/gaussian-elimination"
	"github.com/alex-ant/gomath/rational"
	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/encoding"
	"github.com/ldsec/drynx/lib/range"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"testing"
)

//TestEncodeDecodeLinearRegressionDims tests EncodeLinearRegressionDims and DecodeLinearRegressionDims
func TestEncodeDecodeLinearRegressionDims(t *testing.T) {
	//data
	inputValuesX := [][]int64{{1, 2}, {0, 1}, {1, 0}, {2, 1}, {3, 5}}
	inputValuesY := []int64{11, 5, 3, 9, 27}
	//Solution: c0 = 1, c1 = 2, c2 = 4

	//Input for 1 dimension
	//inputValuesX := [][]int64{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {1}}
	//inputValuesY := []int64{32, 12, 23, 4, 13, -72, 12, 8, 23}

	//dimension
	d := len(inputValuesX[0])

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//Build the augmented matrix
	sumXj := int64(0)
	sumY := int64(0)
	sumXjY := int64(0)
	sumXjXk := int64(0)

	var DataTuple []int64
	DataTuple = append(DataTuple, int64(len(inputValuesX)))

	var StoredVals []int64
	//loop over dimensions
	for j := 0; j < d; j++ {
		sumXj = int64(0)
		sumXjY = int64(0)
		for i := 0; i < len(inputValuesX); i++ {
			x := inputValuesX[i][j]
			sumXj += x
			sumXjY += inputValuesY[i] * x
		}
		DataTuple = append(DataTuple, sumXj)
		StoredVals = append(StoredVals, sumXjY)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sumXjXk = int64(0)
			for i := 0; i < len(inputValuesX); i++ {
				sumXjXk += inputValuesX[i][j] * inputValuesX[i][k]
			}
			DataTuple = append(DataTuple, sumXjXk)
		}
	}

	for _, el := range inputValuesY {
		sumY += el
	}
	DataTuple = append(DataTuple, sumY)
	for j := 0; j < len(StoredVals); j++ {
		DataTuple = append(DataTuple, StoredVals[j])
	}

	matrixAugmented := make([][]int64, d+1, d+2)
	for i := range matrixAugmented {
		matrixAugmented[i] = make([]int64, d+2)
	}

	s := 0
	l := d + 1
	k := d + 1
	i := 0
	for j := 0; j < len(DataTuple)-d-1; j++ {
		if j == l {
			k--
			l = l + k
			i++
			s = 0
		}
		matrixAugmented[i][i+s] = DataTuple[j]
		if i != i+s {
			matrixAugmented[i+s][i] = DataTuple[j]
		}
		s++
	}
	for j := len(DataTuple) - d - 1; j < len(DataTuple); j++ {
		matrixAugmented[j-len(DataTuple)+d+1][d+1] = DataTuple[j]
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

	//Expected results
	coeffsExpected := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffsExpected[i] = solution[i][0].Float64()
	}

	//Actual results
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _ = libdrynxencoding.EncodeLinearRegressionDims(inputValuesX, inputValuesY, pubKey)
	//Testing the length of the encrypted tuple that is sent
	assert.Equal(t, (d*d+5*d+4)/2, len(resultEncrypted))

	coeffsActual := libdrynxencoding.DecodeLinearRegressionDims(resultEncrypted, secKey)
	//Testing the correctness of the coefficient values
	assert.Equal(t, coeffsExpected, coeffsActual)
}

//TestEncodeDecodeLinearRegressionDimsWithProofs tests EncodeLinearRegressionDimsWithProofs and DecodeLinearRegression_DimsWithProofs
func TestEncodeDecodeLinearRegressionDimsWithProofs(t *testing.T) {
	//data
	inputValuesX := [][]int64{{1, 2}, {0, 1}, {1, 0}, {2, 1}, {3, 5}}
	inputValuesY := []int64{11, 5, 3, 9, 27}
	//Solution: c0 = 1, c1 = 2, c2 = 4

	//dimension
	d := len(inputValuesX[0])

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public
	//Build the augmented matrix
	sumXj := int64(0)
	sumY := int64(0)
	sumXjY := int64(0)
	sumXjXk := int64(0)

	var DataTuple []int64
	DataTuple = append(DataTuple, int64(len(inputValuesX)))

	var StoredVals []int64
	//loop over dimensions
	for j := 0; j < d; j++ {
		sumXj = int64(0)
		sumXjY = int64(0)
		for i := 0; i < len(inputValuesX); i++ {
			x := inputValuesX[i][j]
			sumXj += x
			sumXjY += inputValuesY[i] * x
		}
		DataTuple = append(DataTuple, sumXj)
		StoredVals = append(StoredVals, sumXjY)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sumXjXk = int64(0)
			for i := 0; i < len(inputValuesX); i++ {
				sumXjXk += inputValuesX[i][j] * inputValuesX[i][k]
			}
			DataTuple = append(DataTuple, sumXjXk)
		}
	}

	for _, el := range inputValuesY {
		sumY += el
	}
	DataTuple = append(DataTuple, sumY)
	for j := 0; j < len(StoredVals); j++ {
		DataTuple = append(DataTuple, StoredVals[j])
	}

	matrixAugmented := make([][]int64, d+1, d+2)
	for i := range matrixAugmented {
		matrixAugmented[i] = make([]int64, d+2)
	}

	s := 0
	l := d + 1
	k := d + 1
	i := 0
	for j := 0; j < len(DataTuple)-d-1; j++ {
		if j == l {
			k--
			l = l + k
			i++
			s = 0
		}
		matrixAugmented[i][i+s] = DataTuple[j]
		if i != i+s {
			matrixAugmented[i+s][i] = DataTuple[j]
		}
		s++
	}
	for j := len(DataTuple) - d - 1; j < len(DataTuple); j++ {
		matrixAugmented[j-len(DataTuple)+d+1][d+1] = DataTuple[j]
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

	//Expected results
	coeffsExpected := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffsExpected[i] = solution[i][0].Float64()
	}

	lenCiphertext := (d*d + 5*d + 4) / 2
	//signatures needed to check the proof
	u := make([]int64, lenCiphertext)
	l2 := make([]int64, lenCiphertext)

	//Define u and l2, according to the data at hand
	for i := 0; i < len(l2); i++ {
		u[i] = 2
		l2[i] = 8
	}
	ranges := make([]*[]int64, lenCiphertext)
	ps := make([][]libdrynx.PublishSignature, 2)
	ps[0] = make([]libdrynx.PublishSignature, lenCiphertext)
	ps[1] = make([]libdrynx.PublishSignature, lenCiphertext)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, lenCiphertext)
	ys[1] = make([]kyber.Point, lenCiphertext)
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u[i], l2[i]}
	}

	yss := make([][]kyber.Point, lenCiphertext)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//Actual results
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _, prf := libdrynxencoding.EncodeLinearRegressionDimsWithProofs(inputValuesX, inputValuesY, pubKey, ps, ranges)

	//Testing the length of the encrypted tuple that is sent
	assert.Equal(t, (d*d+5*d+4)/2, len(resultEncrypted))

	coeffsActual := libdrynxencoding.DecodeLinearRegressionDims(resultEncrypted, secKey)
	//Testing the correctness of the coefficient values
	assert.Equal(t, coeffsExpected, coeffsActual)

	for i := 0; i < lenCiphertext; i++ {
		//Testing the correctness of the proofs
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[i]), u[i], l2[i], yss[i], pubKey))
	}
}
