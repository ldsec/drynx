package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)

//Note: min and max are such that all values are in the range [min, max], i.e. max (min) is the largest (smallest) possible value the attribute in question can take

//EncodeMinWithProofs encodes the local min
func EncodeMinWithProofs(input []int64, max int64, min int64, pubKey kyber.Point,  sigs [][]libunlynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libunlynx.CreateProof) {
	//compute the local min
	local_min := input[0]
	for _, v := range input {
		if v < local_min {
			local_min = v
		}
	}

	//encode (and encrypt) under OR operation all the bits of min_vector
	Ciphertext_Tuple := make([]libunlynx.CipherText, max-min+1)
	Cleartext_Tuple := make([]int64, max-min+1)
	Proofs_Tuple := make([]libunlynx.CreateProof, max-min+1)
	wg := libunlynx.StartParallelize(int(max-min+1))
	for i := min; i <= max; i++ {
		go func(i int64) {
			defer wg.Done()
			val := false
			if i >= local_min {
				val = true
			}
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, Cleartext_Tuple[i-min], Proofs_Tuple[i-min] = EncodeBit_ORWithProof(val, pubKey, libunlynx.ReadColumn(sigs, int(i-min)),(*lu[i-min])[1], (*lu[i-min])[0])
			} else {
				tmp, Cleartext_Tuple[i-min] = EncodeBit_OR(val, pubKey)
			}
			Ciphertext_Tuple[i-min] = *tmp
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return Ciphertext_Tuple, Cleartext_Tuple, Proofs_Tuple
}

//EncodeMin encodes the local min
func EncodeMin(input []int64, max int64, min int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeMinWithProofs(input, max, min, pubKey, nil, nil)
	return ciphers, clears
}

//DecodeMin decodes the global min
func DecodeMin(result []libunlynx.CipherText, global_min int64, secKey kyber.Scalar) int64 {
	var min int64

	//decode the vector
	bit_is := make([]bool, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bit_is[i] = DecodeBit_OR(result[i], secKey)
		}(i)

	}
	libunlynx.EndParallelize(wg)

	for i := int64(0); i < int64(len(result)); i++ {
		//return the index of the rightmost 1-bit
		if bit_is[i] == true {
			min = i + global_min
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
func EncodeMaxWithProofs(input []int64, max int64, min int64, pubKey kyber.Point,  sigs [][]libunlynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libunlynx.CreateProof) {
	//compute the local max
	local_max := input[0]
	for _, v := range input {
		if v > local_max {
			local_max = v
		}
	}

	//encode (and encrypt) under OR operation all the bits of min_vector
	Cleartext_Tuple := make([]int64, max-min+1)
	Proofs_Tuple := make([]libunlynx.CreateProof, max-min+1)
	Ciphertext_Tuple := make([]libunlynx.CipherText, max-min+1)
	wg := libunlynx.StartParallelize(int(max-min+1))
	for i := min; i <= max; i++ {
		go func(i int64) {
			defer wg.Done()
			val := false
			if i >= local_max {
				val = true
			}
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, Cleartext_Tuple[i-min], Proofs_Tuple[i-min] = EncodeBit_ANDWithProof(val, pubKey, libunlynx.ReadColumn(sigs, int(i-min)),(*lu[i-min])[1], (*lu[i-min])[0])
			} else {
				tmp, Cleartext_Tuple[i-min] = EncodeBit_AND(val, pubKey)
			}
			Ciphertext_Tuple[i-min] = *tmp
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return Ciphertext_Tuple, Cleartext_Tuple, Proofs_Tuple
}

//DecodeMax decodes the global max
func DecodeMax(result []libunlynx.CipherText, global_min int64, secKey kyber.Scalar) int64 {
	var max int64

	//get the counts for all integer values in the range {1, 2, ..., max}
	bit_is := make([]bool, len(result))
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64((len(result))); i++ {
		go func(i int64) {
			defer wg.Done()
			bit_is[i] = DecodeBit_AND(result[i], secKey)
		}(i)

	}
	libunlynx.EndParallelize(wg)

	for i := int64(0); i < int64((len(result))); i++ {
		//return the index of the rightmost 1-bit
		if bit_is[i] == true {
			max = i + global_min
			break
		}
	}
	return max
}
