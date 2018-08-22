package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/proof"
)

//Note: min and max are such that we are examining the attribute's values in the range [min, max]

//EncodeUnion encodes the local union vector
func EncodeUnion(input []int64, min int64, max int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeUnionWithProofs(input, min, max, pubKey, nil, nil)
	return ciphers, clears
}

//EncodeUnionWithProofs encodes the local union vector with range proofs
func EncodeUnionWithProofs(input []int64, min int64, max int64, pubKey kyber.Point,  sigs [][]proof.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []proof.CreateProof) {
	//compute the local min
	//get the set of unique values from the input
	unique_values := Unique(input)

	//encode (and encrypt) under OR operation all the bits of min_vector
	Ciphertext_Tuple := make([]libunlynx.CipherText, max-min+1)
	Cleartext_Tuple := make([]int64, max-min+1)
	Proofs_Tuple := make([]proof.CreateProof, max-min+1)
	filled := make([]bool, max-min+1)
	wg := libunlynx.StartParallelize(len(unique_values))
	for _, entry := range unique_values {
		go func(entry int64) {
			defer wg.Done()
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, Cleartext_Tuple[entry-min], Proofs_Tuple[entry-min] = EncodeBit_ORWithProof(true, pubKey, proof.ReadColumn(sigs, int(entry-min)),(*lu[entry-min])[1], (*lu[entry-min])[0])
			} else {
				tmp, Cleartext_Tuple[entry-min] = EncodeBit_OR(true, pubKey)
			}
			Ciphertext_Tuple[entry-min] = *tmp
			filled[entry-min] = true
		}(entry)
	}
	libunlynx.EndParallelize(wg)
	wg1 := libunlynx.StartParallelize(len(Ciphertext_Tuple))
	for i := int64(0); i < int64(len(Ciphertext_Tuple)); i++ {
		go func(i int64) {
			defer wg1.Done()
			if !filled[i] {
				tmp := &libunlynx.CipherText{}
				if sigs != nil {
					tmp, Cleartext_Tuple[i], Proofs_Tuple[i] = EncodeBit_ORWithProof(false, pubKey, proof.ReadColumn(sigs, int(i)),(*lu[i])[1], (*lu[i])[0])
				} else {
					tmp, Cleartext_Tuple[i] = EncodeBit_OR(false, pubKey)
				}
				Ciphertext_Tuple[i] = *tmp
			}
		}(i)

	}
	libunlynx.EndParallelize(wg1)

	return Ciphertext_Tuple, Cleartext_Tuple, Proofs_Tuple
}

//DecodeUnion decodes the global union vector
func DecodeUnion(result []libunlynx.CipherText, secKey kyber.Scalar) []int64 {
	output_vector := make([]int64, len(result))
	//decode the vector
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bit_i := DecodeBit_OR(result[i], secKey)
			//return the index of the rightmost 1-bit
			if bit_i == true {
				output_vector[i] = 1
			} else {
				output_vector[i] = 0
			}
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return output_vector
}

//EncodeInter encodes the local intersection vector
func EncodeInter(input []int64, min int64, max int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeInterWithProofs(input, min, max, pubKey, nil, nil)
	return ciphers, clears
}

//EncodeInterWithProofs encodes the local intersection vector with range proofs
func EncodeInterWithProofs(input []int64, min int64, max int64, pubKey kyber.Point,  sigs [][]proof.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []proof.CreateProof) {
	//get the set of unique values from the input
	unique_values := Unique(input)
	Ciphertext_Tuple := make([]libunlynx.CipherText, max-min+1)
	Cleartext_Tuple := make([]int64, max-min+1)
	Proofs_Tuple := make([]proof.CreateProof, max-min+1)
	filled := make([]bool, max-min+1)
	wg := libunlynx.StartParallelize(len(unique_values))
	for _, entry := range unique_values {
		go func(entry int64) {
			defer wg.Done()
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, Cleartext_Tuple[entry-min], Proofs_Tuple[entry-min] = EncodeBit_ANDWithProof(true, pubKey, proof.ReadColumn(sigs, int(entry-min)),(*lu[entry-min])[1], (*lu[entry-min])[0])
			} else {
				tmp, Cleartext_Tuple[entry-min] = EncodeBit_AND(true, pubKey)
			}
			Ciphertext_Tuple[entry-min] = *tmp
			filled[entry-min] = true
		}(entry)

	}
	libunlynx.EndParallelize(wg)
	wg1 := libunlynx.StartParallelize(len(Ciphertext_Tuple))
	for i := int64(0); i < int64(len(Ciphertext_Tuple)); i++ {
		go func(i int64) {
			defer wg1.Done()
			if !filled[i] {
				tmp := &libunlynx.CipherText{}
				if sigs != nil {
					tmp, Cleartext_Tuple[i], Proofs_Tuple[i] = EncodeBit_ANDWithProof(false, pubKey, proof.ReadColumn(sigs, int(i)),(*lu[i])[1], (*lu[i])[0])
				} else {
					tmp, Cleartext_Tuple[i] = EncodeBit_AND(false, pubKey)
				}
				Ciphertext_Tuple[i] = *tmp
			}
		}(i)
	}
	libunlynx.EndParallelize(wg1)

	return Ciphertext_Tuple, Cleartext_Tuple, Proofs_Tuple
}

//DecodeInter decodes the global intersection vector
func DecodeInter(result []libunlynx.CipherText, secKey kyber.Scalar) []int64 {
	output_vector := make([]int64, len(result))
	//decode the vector
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bit_i := DecodeBit_AND(result[i], secKey)
			//return the index of the rightmost 1-bit
			if bit_i == true {
				output_vector[i] = 1
			} else {
				output_vector[i] = 0
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)
	return output_vector
}

// Unique returns a list of the unique elements from a list of int64
func Unique(intSlice []int64) []int64 {
	keys := make(map[int64]bool)
	var list []int64
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
