package encoding

import (
	"go.dedis.ch/kyber/v3"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
)

//Note: min and max are such that all values are in the range [min, max], i.e. max (min) is the largest (smallest) possible value the attribute in question can take

//EncodeMinWithProofs encodes the local min
func EncodeMinWithProofs(input []int64, max int64, min int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//compute the local min
	localMin := input[0]
	for _, v := range input {
		if v < localMin {
			localMin = v
		}
	}

	//encode (and encrypt) under OR operation all the bits of min_vector
	ciphertextTuple := make([]libunlynx.CipherText, max-min+1)
	cleartextTuples := make([]int64, max-min+1)
	proofsTuples := make([]libdrynx.CreateProof, max-min+1)
	wg := libunlynx.StartParallelize(int(max - min + 1))
	for i := min; i <= max; i++ {
		go func(i int64) {
			defer wg.Done()
			val := false
			if i >= localMin {
				val = true
			}
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, cleartextTuples[i-min], proofsTuples[i-min] = EncodeBitOrWithProof(val, pubKey, libdrynx.ReadColumn(sigs, int(i-min)), (*lu[i-min])[1], (*lu[i-min])[0])
			} else {
				tmp, cleartextTuples[i-min] = EncodeBitOr(val, pubKey)
			}
			ciphertextTuple[i-min] = *tmp
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return ciphertextTuple, cleartextTuples, proofsTuples
}

//EncodeMin encodes the local min
func EncodeMin(input []int64, max int64, min int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeMinWithProofs(input, max, min, pubKey, nil, nil)
	return ciphers, clears
}

//DecodeMin decodes the global min
func DecodeMin(result []libunlynx.CipherText, globalMin int64, secKey kyber.Scalar) int64 {
	var min int64

	//decode the vector
	bitIs := make([]bool, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bitIs[i] = DecodeBitOR(result[i], secKey)
		}(i)

	}
	libunlynx.EndParallelize(wg)

	for i := int64(0); i < int64(len(result)); i++ {
		//return the index of the rightmost 1-bit
		if bitIs[i] == true {
			min = i + globalMin
			break
		}
	}
	return min
}

//EncodeMax encodes the local min
func EncodeMax(input []int64, max int64, min int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeMaxWithProofs(input, max, min, pubKey, nil, nil)
	return ciphers, clears
}

//EncodeMaxWithProofs encodes the local max
func EncodeMaxWithProofs(input []int64, max int64, min int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//compute the local max
	localMax := input[0]
	for _, v := range input {
		if v > localMax {
			localMax = v
		}
	}

	//encode (and encrypt) under OR operation all the bits of min_vector
	cleartextTuples := make([]int64, max-min+1)
	proofsTuples := make([]libdrynx.CreateProof, max-min+1)
	ciphertextTuples := make([]libunlynx.CipherText, max-min+1)
	wg := libunlynx.StartParallelize(int(max - min + 1))
	for i := min; i <= max; i++ {
		go func(i int64) {
			defer wg.Done()
			val := false
			if i >= localMax {
				val = true
			}
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, cleartextTuples[i-min], proofsTuples[i-min] = EncodeBitANDWithProof(val, pubKey, libdrynx.ReadColumn(sigs, int(i-min)), (*lu[i-min])[1], (*lu[i-min])[0])
			} else {
				tmp, cleartextTuples[i-min] = EncodeBitAND(val, pubKey)
			}
			ciphertextTuples[i-min] = *tmp
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return ciphertextTuples, cleartextTuples, proofsTuples
}

//DecodeMax decodes the global max
func DecodeMax(result []libunlynx.CipherText, globalMin int64, secKey kyber.Scalar) int64 {
	var max int64

	//get the counts for all integer values in the range {1, 2, ..., max}
	bitIs := make([]bool, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bitIs[i] = DecodeBitAND(result[i], secKey)
		}(i)

	}
	libunlynx.EndParallelize(wg)

	for i := int64(0); i < int64(len(result)); i++ {
		//return the index of the rightmost 1-bit
		if bitIs[i] == true {
			max = i + globalMin
			break
		}
	}
	return max
}
