package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/proof"
)

//EncodeFreqCount computes the frequency count of query results
//Note: min and max are such that all values are in the range [min, max], i.e. max (min) is the largest (smallest) possible value the attribute in question can take
func EncodeFreqCount(input []int64, min int64, max int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeFreqCountWithProofs(input, min, max, pubKey, nil, nil)
	return resultEnc, resultClear
}

// EncodeFreqCountWithProofs computes the frequency count of query results with the proof of range
func EncodeFreqCountWithProofs(input []int64, min int64, max int64, pubKey kyber.Point, sigs [][]proof.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []proof.CreateProof) {
	freqcount := make([]int64, max-min+1)
	r := make([]kyber.Scalar, max-min+1)

	for i := 0; int64(i) <= max-min; i++ {
		freqcount[i] = 0
	}
	//get the frequency count for all integer values in the range {min, min+1, ..., max}
	for _, el := range input {
		freqcount[el-min] += 1
	}

	//encrypt the local DP's query results
	Ciphertext_Tuple := make([]libunlynx.CipherText, max-min+1)
	wg := libunlynx.StartParallelize(int(max-min)+1)
	for i := int64(0); i <= max-min; i++ {
		go func(i int64) {
			defer wg.Done()
			count_i_Encrypted, r_i := libunlynx.EncryptIntGetR(pubKey, freqcount[i])
			r[i] = r_i
			Ciphertext_Tuple[i] = *count_i_Encrypted
		}(i)

	}
	libunlynx.EndParallelize(wg)

	if sigs == nil {
		return Ciphertext_Tuple, []int64{0}, nil
	}

	createRangeProof := make([]proof.CreateProof, len(freqcount))
	wg1 := libunlynx.StartParallelize(len(freqcount))
	for i, v := range freqcount {
		if libunlynx.PARALLELIZE {
			go func(i int, v int64) {
				defer wg1.Done()
				//input range validation proof
				createRangeProof[i] = proof.CreateProof{Sigs: proof.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
			}(i, v)
		} else {
			//input range validation proof
			createRangeProof[i] = proof.CreateProof{Sigs: proof.ReadColumn(sigs, i), U: (*lu[i])[0], L: (*lu[i])[1], Secret: v, R: r[i], CaPub: pubKey, Cipher: Ciphertext_Tuple[i]}
		}
	}
	libunlynx.EndParallelize(wg1)
	return Ciphertext_Tuple, []int64{0}, createRangeProof
}

//DecodeFreqCount computes the frequency count of local DP's query results
func DecodeFreqCount(result []libunlynx.CipherText, secKey kyber.Scalar) []int64 {
	Plaintext_Tuple := make([]int64, len(result))

	//get the counts for all integer values in the range {1, 2, ..., max}
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			Plaintext_Tuple[i] = libunlynx.DecryptIntWithNeg(secKey, result[i])
		}(i)

	}
	libunlynx.EndParallelize(wg)

	//return the array of counts
	return Plaintext_Tuple
}
