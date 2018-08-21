package encoding_test

import (
	"github.com/alex-ant/gomath/gaussian-elimination"
	"github.com/alex-ant/gomath/rational"
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/encoding"
	"github.com/stretchr/testify/assert"
	"testing"
)

//TestEncodeDecodeLinearRegressionDims tests EncodeLinearRegression_Dims and DecodeLinearRegression_Dims
func TestEncodeDecodeLinearRegressionDims(t *testing.T) {
	//data
	inputValues_x := [][]int64{{1, 2}, {0, 1}, {1, 0}, {2, 1}, {3, 5}}
	inputValues_y := []int64{11, 5, 3, 9, 27}
	//Solution: c0 = 1, c1 = 2, c2 = 4

	//Input for 1 dimension
	//inputValues_x := [][]int64{{1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {1}}
	//inputValues_y := []int64{32, 12, 23, 4, 13, -72, 12, 8, 23}

	//dimension
	d := len(inputValues_x[0])

	// key
	secKey, pubKey := libunlynx.GenKey()
	//Build the augmented matrix
	sum_xj := int64(0)
	sum_y := int64(0)
	sum_xj_y := int64(0)
	sum_xj_xk := int64(0)

	var Data_Tuple []int64
	Data_Tuple = append(Data_Tuple, int64(len(inputValues_x)))

	var StoredVals []int64
	//loop over dimensions
	for j := 0; j < d; j++ {
		sum_xj = int64(0)
		sum_xj_y = int64(0)
		for i := 0; i < len(inputValues_x); i++ {
			x := inputValues_x[i][j]
			sum_xj += x
			sum_xj_y += inputValues_y[i] * x
		}
		Data_Tuple = append(Data_Tuple, sum_xj)
		StoredVals = append(StoredVals, sum_xj_y)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sum_xj_xk = int64(0)
			for i := 0; i < len(inputValues_x); i++ {
				sum_xj_xk += inputValues_x[i][j] * inputValues_x[i][k]
			}
			Data_Tuple = append(Data_Tuple, sum_xj_xk)
		}
	}

	for _, el := range inputValues_y {
		sum_y += el
	}
	Data_Tuple = append(Data_Tuple, sum_y)
	for j := 0; j < len(StoredVals); j++ {
		Data_Tuple = append(Data_Tuple, StoredVals[j])
	}

	matrix_augmented := make([][]int64, d+1, d+2)
	for i := range matrix_augmented {
		matrix_augmented[i] = make([]int64, d+2)
	}

	s := 0
	l := d + 1
	k := d + 1
	i := 0
	for j := 0; j < len(Data_Tuple)-d-1; j++ {
		if j == l {
			k--
			l = l + k
			i++
			s = 0
		}
		matrix_augmented[i][i+s] = Data_Tuple[j]
		if i != i+s {
			matrix_augmented[i+s][i] = Data_Tuple[j]
		}
		s++
	}
	for j := len(Data_Tuple) - d - 1; j < len(Data_Tuple); j++ {
		matrix_augmented[j-len(Data_Tuple)+d+1][d+1] = Data_Tuple[j]
	}

	matrix_rational := make([][]rational.Rational, d+1, d+2)
	for i := range matrix_augmented {
		matrix_rational[i] = make([]rational.Rational, d+2)
	}
	for i := range matrix_augmented {
		for j := 0; j < d+2; j++ {
			matrix_rational[i][j] = rational.New(matrix_augmented[i][j], 1)
		}
	}

	//Solve the linear system of equations and return x = [c0, c1, c2, ..., cd]
	var solution [][]rational.Rational
	solution, _ = gaussian.SolveGaussian(matrix_rational, false)

	//Expected results
	coeffs_expected := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffs_expected[i] = solution[i][0].Float64()
	}

	//Actual results
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _ = encoding.EncodeLinearRegression_Dims(inputValues_x, inputValues_y, pubKey)
	//Testing the length of the encrypted tuple that is sent
	assert.Equal(t, (d*d+5*d+4)/2, len(resultEncrypted))

	coeffs_actual := encoding.DecodeLinearRegression_Dims(resultEncrypted, secKey)
	//Testing the correctness of the coefficient values
	assert.Equal(t, coeffs_expected, coeffs_actual)
}

//TestEncodeDecodeLinearRegressionDimsWithProofs tests EncodeLinearRegression_DimsWithProofs and DecodeLinearRegression_DimsWithProofs
func TestEncodeDecodeLinearRegressionDimsWithProofs(t *testing.T) {
	//data
	inputValues_x := [][]int64{{1, 2}, {0, 1}, {1, 0}, {2, 1}, {3, 5}}
	inputValues_y := []int64{11, 5, 3, 9, 27}
	//Solution: c0 = 1, c1 = 2, c2 = 4

	//dimension
	d := len(inputValues_x[0])

	// key
	secKey, pubKey := libunlynx.GenKey()
	//Build the augmented matrix
	sum_xj := int64(0)
	sum_y := int64(0)
	sum_xj_y := int64(0)
	sum_xj_xk := int64(0)

	var Data_Tuple []int64
	Data_Tuple = append(Data_Tuple, int64(len(inputValues_x)))

	var StoredVals []int64
	//loop over dimensions
	for j := 0; j < d; j++ {
		sum_xj = int64(0)
		sum_xj_y = int64(0)
		for i := 0; i < len(inputValues_x); i++ {
			x := inputValues_x[i][j]
			sum_xj += x
			sum_xj_y += inputValues_y[i] * x
		}
		Data_Tuple = append(Data_Tuple, sum_xj)
		StoredVals = append(StoredVals, sum_xj_y)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sum_xj_xk = int64(0)
			for i := 0; i < len(inputValues_x); i++ {
				sum_xj_xk += inputValues_x[i][j] * inputValues_x[i][k]
			}
			Data_Tuple = append(Data_Tuple, sum_xj_xk)
		}
	}

	for _, el := range inputValues_y {
		sum_y += el
	}
	Data_Tuple = append(Data_Tuple, sum_y)
	for j := 0; j < len(StoredVals); j++ {
		Data_Tuple = append(Data_Tuple, StoredVals[j])
	}

	matrix_augmented := make([][]int64, d+1, d+2)
	for i := range matrix_augmented {
		matrix_augmented[i] = make([]int64, d+2)
	}

	s := 0
	l := d + 1
	k := d + 1
	i := 0
	for j := 0; j < len(Data_Tuple)-d-1; j++ {
		if j == l {
			k--
			l = l + k
			i++
			s = 0
		}
		matrix_augmented[i][i+s] = Data_Tuple[j]
		if i != i+s {
			matrix_augmented[i+s][i] = Data_Tuple[j]
		}
		s++
	}
	for j := len(Data_Tuple) - d - 1; j < len(Data_Tuple); j++ {
		matrix_augmented[j-len(Data_Tuple)+d+1][d+1] = Data_Tuple[j]
	}

	matrix_rational := make([][]rational.Rational, d+1, d+2)
	for i := range matrix_augmented {
		matrix_rational[i] = make([]rational.Rational, d+2)
	}
	for i := range matrix_augmented {
		for j := 0; j < d+2; j++ {
			matrix_rational[i][j] = rational.New(matrix_augmented[i][j], 1)
		}
	}

	//Solve the linear system of equations and return x = [c0, c1, c2, ..., cd]
	var solution [][]rational.Rational
	solution, _ = gaussian.SolveGaussian(matrix_rational, false)

	//Expected results
	coeffs_expected := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffs_expected[i] = solution[i][0].Float64()
	}

	len_ciphertext := (d*d + 5*d + 4) / 2
	//signatures needed to check the proof
	u := make([]int64, len_ciphertext)
	l2 := make([]int64, len_ciphertext)

	//Define u and l2, according to the data at hand
	for i := 0; i < len(l2); i++ {
		u[i] = 2
		l2[i] = 8
	}
	ranges := make([]*[]int64, len_ciphertext)
	ps := make([][]libunlynx.PublishSignature, 2)
	ps[0] = make([]libunlynx.PublishSignature, len_ciphertext)
	ps[1] = make([]libunlynx.PublishSignature, len_ciphertext)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, len_ciphertext)
	ys[1] = make([]kyber.Point, len_ciphertext)
	for i := range ps[0] {
		ps[0][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u[i]))
		ps[1][i] = libunlynx.PublishSignatureBytesToPublishSignatures(libunlynx.InitRangeProofSignature(u[i]))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u[i], l2[i]}
	}

	yss := make([][]kyber.Point, len_ciphertext)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//Actual results
	var resultEncrypted []libunlynx.CipherText
	resultEncrypted, _, prf := encoding.EncodeLinearRegression_DimsWithProofs(inputValues_x, inputValues_y, pubKey, ps, ranges)

	//Testing the length of the encrypted tuple that is sent
	assert.Equal(t, (d*d+5*d+4)/2, len(resultEncrypted))

	coeffs_actual := encoding.DecodeLinearRegression_Dims(resultEncrypted, secKey)
	//Testing the correctness of the coefficient values
	assert.Equal(t, coeffs_expected, coeffs_actual)

	for i := 0; i < len_ciphertext; i++ {
		//Testing the correctness of the proofs
		assert.True(t, libunlynx.RangeProofVerification(libunlynx.CreatePredicateRangeProofForAllServ(prf[i]), u[i], l2[i], yss[i], pubKey))
	}
}
