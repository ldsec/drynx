package encoding

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
)

//Note: min and max are such that we are examining the attribute's values in the range [min, max]

//EncodeUnion encodes the local union vector
func EncodeUnion(input []int64, min int64, max int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeUnionWithProofs(input, min, max, pubKey, nil, nil)
	return ciphers, clears
}

//EncodeUnionWithProofs encodes the local union vector with range proofs
func EncodeUnionWithProofs(input []int64, min int64, max int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//compute the local min
	//get the set of unique values from the input
	uniqueValues := Unique(input)

	//encode (and encrypt) under OR operation all the bits of min_vector
	ciphertextTuples := make([]libunlynx.CipherText, max-min+1)
	cleartextTuples := make([]int64, max-min+1)
	proofsTuples := make([]libdrynx.CreateProof, max-min+1)
	filled := make([]bool, max-min+1)
	wg := libunlynx.StartParallelize(len(uniqueValues))
	for _, entry := range uniqueValues {
		go func(entry int64) {
			defer wg.Done()
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, cleartextTuples[entry-min], proofsTuples[entry-min] = EncodeBitOrWithProof(true, pubKey, libdrynx.ReadColumn(sigs, int(entry-min)), (*lu[entry-min])[1], (*lu[entry-min])[0])
			} else {
				tmp, cleartextTuples[entry-min] = EncodeBitOr(true, pubKey)
			}
			ciphertextTuples[entry-min] = *tmp
			filled[entry-min] = true
		}(entry)
	}
	libunlynx.EndParallelize(wg)
	wg1 := libunlynx.StartParallelize(len(ciphertextTuples))
	for i := int64(0); i < int64(len(ciphertextTuples)); i++ {
		go func(i int64) {
			defer wg1.Done()
			if !filled[i] {
				tmp := &libunlynx.CipherText{}
				if sigs != nil {
					tmp, cleartextTuples[i], proofsTuples[i] = EncodeBitOrWithProof(false, pubKey, libdrynx.ReadColumn(sigs, int(i)), (*lu[i])[1], (*lu[i])[0])
				} else {
					tmp, cleartextTuples[i] = EncodeBitOr(false, pubKey)
				}
				ciphertextTuples[i] = *tmp
			}
		}(i)

	}
	libunlynx.EndParallelize(wg1)

	return ciphertextTuples, cleartextTuples, proofsTuples
}

//DecodeUnion decodes the global union vector
func DecodeUnion(result []libunlynx.CipherText, secKey kyber.Scalar) []int64 {
	outputVectors := make([]int64, len(result))
	//decode the vector
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bitI := DecodeBitOR(result[i], secKey)
			//return the index of the rightmost 1-bit
			if bitI == true {
				outputVectors[i] = 1
			} else {
				outputVectors[i] = 0
			}
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return outputVectors
}

//EncodeInter encodes the local intersection vector
func EncodeInter(input []int64, min int64, max int64, pubKey kyber.Point) ([]libunlynx.CipherText, []int64) {
	ciphers, clears, _ := EncodeInterWithProofs(input, min, max, pubKey, nil, nil)
	return ciphers, clears
}

//EncodeInterWithProofs encodes the local intersection vector with range proofs
func EncodeInterWithProofs(input []int64, min int64, max int64, pubKey kyber.Point, sigs [][]libdrynx.PublishSignature, lu []*[]int64) ([]libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//get the set of unique values from the input
	uniqueValues := Unique(input)
	ciphertextTuples := make([]libunlynx.CipherText, max-min+1)
	cleartextTuples := make([]int64, max-min+1)
	proofsTuples := make([]libdrynx.CreateProof, max-min+1)
	filled := make([]bool, max-min+1)
	wg := libunlynx.StartParallelize(len(uniqueValues))
	for _, entry := range uniqueValues {
		go func(entry int64) {
			defer wg.Done()
			tmp := &libunlynx.CipherText{}
			if sigs != nil {
				tmp, cleartextTuples[entry-min], proofsTuples[entry-min] = EncodeBitANDWithProof(true, pubKey, libdrynx.ReadColumn(sigs, int(entry-min)), (*lu[entry-min])[1], (*lu[entry-min])[0])
			} else {
				tmp, cleartextTuples[entry-min] = EncodeBitAND(true, pubKey)
			}
			ciphertextTuples[entry-min] = *tmp
			filled[entry-min] = true
		}(entry)

	}
	libunlynx.EndParallelize(wg)
	wg1 := libunlynx.StartParallelize(len(ciphertextTuples))
	for i := int64(0); i < int64(len(ciphertextTuples)); i++ {
		go func(i int64) {
			defer wg1.Done()
			if !filled[i] {
				tmp := &libunlynx.CipherText{}
				if sigs != nil {
					tmp, cleartextTuples[i], proofsTuples[i] = EncodeBitANDWithProof(false, pubKey, libdrynx.ReadColumn(sigs, int(i)), (*lu[i])[1], (*lu[i])[0])
				} else {
					tmp, cleartextTuples[i] = EncodeBitAND(false, pubKey)
				}
				ciphertextTuples[i] = *tmp
			}
		}(i)
	}
	libunlynx.EndParallelize(wg1)

	return ciphertextTuples, cleartextTuples, proofsTuples
}

//DecodeInter decodes the global intersection vector
func DecodeInter(result []libunlynx.CipherText, secKey kyber.Scalar) []int64 {
	outputVectors := make([]int64, len(result))
	//decode the vector
	wg := libunlynx.StartParallelize(len(result))
	for i := int64(0); i < int64(len(result)); i++ {
		go func(i int64) {
			defer wg.Done()
			bitI := DecodeBitAND(result[i], secKey)
			//return the index of the rightmost 1-bit
			if bitI == true {
				outputVectors[i] = 1
			} else {
				outputVectors[i] = 0
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)
	return outputVectors
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
