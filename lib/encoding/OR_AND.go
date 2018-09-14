package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber/util/random"
	"github.com/lca1/drynx/lib"
)

//d in this case is (modulus - 2 = 2^255 - 19 - 2 = 2^255 - 21)
//This is because the random number R we want to generate should be in the set {1, 2, ..., modulus -1}
//But in this case with golang, we are generating it from the range [0, modulus-2] and then adding 1 to it
// to make sure that it belongs to the range [1, modulus - 1]

//EncodeBit_OR computes the encoding of bit Xi, under the OR operation
func EncodeBit_OR(input bool, pubKey kyber.Point) (*libunlynx.CipherText, int64) {
	cipher, clear, _ := EncodeBit_ORWithProof(input, pubKey,  nil, 0, 0)
	return cipher, clear
}

//EncodeBit_ORWithProof computes the encoding of bit Xi, under the OR operation with range proofs
func EncodeBit_ORWithProof(input bool, pubKey kyber.Point, sigs []libdrynx.PublishSignature, l int64, u int64) (*libunlynx.CipherText, int64, libdrynx.CreateProof) {
	cipher := libunlynx.CipherText{}
	toEncrypt := int64(0)
	cp := libdrynx.CreateProof{}
	if sigs != nil {
		if input {
			toEncrypt = int64(1)
		}
		tmp,r := libdrynx.EncryptIntGetR(pubKey, toEncrypt)
		cipher = *tmp
		//input range validation proof
		cp = libdrynx.CreateProof{Sigs: sigs, U: u, L: l, Secret: toEncrypt, R: r, CaPub: pubKey, Cipher: cipher}

	} else {
		Random_Scalar := libunlynx.SuiTe.Scalar().Zero()
		Zero := libunlynx.SuiTe.Scalar().Zero()
		if input == true {
			//generate random number using Scalar
			Random_Scalar = libunlynx.SuiTe.Scalar().Pick(random.New())
			//keep generating random numbers until we get a non-zero one
			for i := 0; i <= 10; i++ {
				if Random_Scalar == Zero {
					Random_Scalar = libunlynx.SuiTe.Scalar().Pick(random.New())
				} else {
					break
				}
			}
		}
		//encrypt the local representation of the bit
		cipher = *libunlynx.EncryptScalar(pubKey, Random_Scalar)
	}

	return &cipher, toEncrypt, cp
}

//DecodeBit_OR computes the decoding of bit Xi, under the OR operation
func DecodeBit_OR(result libunlynx.CipherText, secKey kyber.Scalar) bool {
	//decrypt the bit representation
	output := libunlynx.DecryptCheckZero(secKey, result)
	//as per our convention, if R > 0, then the corresponding bit is a 1, else it is a 0
	if output == int64(0) {
		return false
	}
	return true
}

//EncodeBit_AND computes the encoding of bit Xi, under the AND operation
func EncodeBit_AND(input bool, pubKey kyber.Point) (*libunlynx.CipherText, int64) {
	cipher, clear, _ := EncodeBit_ANDWithProof(input, pubKey,  nil, 0, 0)
	return cipher, clear
}

//EncodeBit_AND computes the encoding of bit Xi, under the AND operation with range proofs
func EncodeBit_ANDWithProof(input bool, pubKey kyber.Point, sigs []libdrynx.PublishSignature, l int64, u int64) (*libunlynx.CipherText, int64, libdrynx.CreateProof) {
	cipher := libunlynx.CipherText{}
	toEncrypt := int64(1)
	cp := libdrynx.CreateProof{}
	if sigs != nil {
		if input {
			toEncrypt = int64(0)
		}
		tmp,r := libdrynx.EncryptIntGetR(pubKey, toEncrypt)
		cipher = *tmp
		//input range validation proof
		cp = libdrynx.CreateProof{Sigs: sigs, U: u, L: l, Secret: toEncrypt, R: r, CaPub: pubKey, Cipher: cipher}

	} else {
		Random_Scalar := libunlynx.SuiTe.Scalar().Zero()
		Zero := libunlynx.SuiTe.Scalar().Zero()
		if input == false {
			//generate random number using Scalar
			Random_Scalar = libunlynx.SuiTe.Scalar().Pick(random.New())
			//keep generating random numbers until we get a non-zero one
			for i := 0; i <= 10; i++ {
				if Random_Scalar == Zero {
					Random_Scalar = libunlynx.SuiTe.Scalar().Pick(random.New())
				} else {
					break
				}
			}
		}
		//encrypt the local representation of the bit
		cipher = *libunlynx.EncryptScalar(pubKey, Random_Scalar)
	}

	return &cipher, toEncrypt, cp
}

//DecodeBit_AND computes the decoding of bit Xi, under the AND operation
func DecodeBit_AND(result libunlynx.CipherText, secKey kyber.Scalar) bool {
	//decrypt the bit representation
	output := libunlynx.DecryptCheckZero(secKey, result)
	//as per our convention, if R > 0, then the corresponding bit is a 1, else it is a 0
	if output == int64(0) {
		return true
	}
	return false
}

//LocalResult_OR calculates the local result of the OR operation over all boolean values of the input array
func LocalResult_OR(input []bool) bool {
	local_result := false
	for i := int64(0); i < int64(len(input)); i++ {
		if input[i] == true {
			local_result = true
			break
		}
	}
	return local_result
}

//LocalResult_AND calculates the local result of the AND operation over all boolean values of the input array
func LocalResult_AND(input []bool) bool {
	local_result := true
	for i := int64(0); i < int64(len(input)); i++ {
		if input[i] == false {
			local_result = false
			break
		}
	}
	return local_result
}
