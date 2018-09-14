package encoding

import (
	"github.com/alex-ant/gomath/gaussian-elimination"
	"github.com/alex-ant/gomath/rational"
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/tonestuff/quadratic"
	"github.com/lca1/drynx/lib"
)

//EncodeLinearRegression_Dims implements a d-dimensional linear regression algorithm on the query results
func EncodeLinearRegression_Dims(input1 [][]int64, input2 []int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeLinearRegression_DimsWithProofs(input1, input2, pubKey, nil, nil)
	return resultEnc, resultClear
}

//EncodeLinearRegression_DimsWithProofs implements a d-dimensional linear regression algorithm on the query results with range proofs
func EncodeLinearRegression_DimsWithProofs(input1 [][]int64, input2 []int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//sum the Xs and their squares, the Ys and the product of every pair of X and Y
	sum_xj := int64(0)
	sum_y := int64(0)
	sum_xj_y := int64(0)
	sum_xj_xk := int64(0)

	//Input dimension
	d := len(input1[0])
	//Input number of Samples
	N := len(input1)

	var plaintext_values []int64
	var r []kyber.Scalar

	var Ciphertext_Tuple []libunlynx.CipherText
	//Encrypt the number of data records considered
	N_Encrypted, r_0 := libdrynx.EncryptIntGetR(pubKey, int64(N))
	Ciphertext_Tuple = append(Ciphertext_Tuple, *N_Encrypted)
	plaintext_values = append(plaintext_values, int64(N))
	r = append(r, r_0)

	var StoredVals []int64

	//loop over dimensions
	for j := 0; j < d; j++ {
		sum_xj = int64(0)
		sum_xj_y = int64(0)
		for i := 0; i < N; i++ {
			x := input1[i][j]
			sum_xj += x
			sum_xj_y += input2[i] * x
		}
		sum_xj_Encrypted, r_temp := libdrynx.EncryptIntGetR(pubKey, sum_xj)
		Ciphertext_Tuple = append(Ciphertext_Tuple, *sum_xj_Encrypted)
		plaintext_values = append(plaintext_values, sum_xj)
		r = append(r, r_temp)
		StoredVals = append(StoredVals, sum_xj_y)
	}

	for j := 0; j < d; j++ {
		for k := j; k < d; k++ {
			sum_xj_xk = int64(0)
			for i := 0; i < N; i++ {
				sum_xj_xk += input1[i][j] * input1[i][k]
			}
			sum_xj_xk_Encrypted, r_temp := libdrynx.EncryptIntGetR(pubKey, sum_xj_xk)
			Ciphertext_Tuple = append(Ciphertext_Tuple, *sum_xj_xk_Encrypted)
			plaintext_values = append(plaintext_values, sum_xj_xk)
			r = append(r, r_temp)
		}
	}

	for _, el := range input2 {
		sum_y += el
	}
	sum_y_Encrypted, r_y := libdrynx.EncryptIntGetR(pubKey, sum_y)
	Ciphertext_Tuple = append(Ciphertext_Tuple, *sum_y_Encrypted)
	plaintext_values = append(plaintext_values, sum_y)
	r = append(r, r_y)

	for j := 0; j < len(StoredVals); j++ {
		sum_xj_y_Encrypted, r_temp := libdrynx.EncryptIntGetR(pubKey, StoredVals[j])
		Ciphertext_Tuple = append(Ciphertext_Tuple, *sum_xj_y_Encrypted)
		plaintext_values = append(plaintext_values, StoredVals[j])
		r = append(r, r_temp)
	}

	if sigs == nil {
		return Ciphertext_Tuple, []int64{0}, nil
	}
	//input range validation proof
	createProofs := make([]libdrynx.CreateProof, len(plaintext_values))
	wg := libunlynx.StartParallelize(len(plaintext_values))
	for i, v := range plaintext_values {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg.Done()
				//input range validation proof
				createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
			}(i, v)
		} else {
			//input range validation proof
			createProofs[i] = libdrynx.CreateProof{Sigs: libdrynx.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
		}
	}
	libunlynx.EndParallelize(wg)
	return Ciphertext_Tuple, []int64{0}, createProofs
}

//DecodeLinearRegression_Dims implements a d-dimensional linear regression algorithm, in this encoding, we assume the system to have a perfect solution
//TODO least-square computation and not equality
func DecodeLinearRegression_Dims(result []libunlynx.CipherText, secKey kyber.Scalar) []float64 {
	//get the the number of dimensions by solving the equation: d^2 + 5d + 4 = 2*len(result)
	pos_sol, _ := quadratic.Solve(1, 5, complex128(complex(float32(4-2*len(result)), 0)))
	d := int(real(pos_sol))

	matrix_augmented := make([][]int64, d+1, d+2)
	for i := range matrix_augmented {
		matrix_augmented[i] = make([]int64, d+2)
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
		matrix_augmented[i][i+s] = libunlynx.DecryptIntWithNeg(secKey, result[j])
		if i != i+s {
			matrix_augmented[i+s][i] = libunlynx.DecryptIntWithNeg(secKey, result[j])
		}
		s++
	}

	for j := len(result) - d - 1; j < len(result); j++ {
		matrix_augmented[j-len(result)+d+1][d+1] = libunlynx.DecryptIntWithNeg(secKey, result[j])
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

	coeffs := make([]float64, d+1)
	for i := 0; i < len(solution); i++ {
		coeffs[i] = solution[i][0].Float64()
	}
	return coeffs
}
