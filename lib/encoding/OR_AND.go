package encoding

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

//d in this case is (modulus - 2 = 2^255 - 19 - 2 = 2^255 - 21)
//This is because the random number R we want to generate should be in the set {1, 2, ..., modulus -1}
//But in this case with golang, we are generating it from the range [0, modulus-2] and then adding 1 to it
// to make sure that it belongs to the range [1, modulus - 1]

//EncodeBitOr computes the encoding of bit Xi, under the OR operation
func EncodeBitOr(input bool, pubKey kyber.Point) (*libunlynx.CipherText, int64) {
	cipher, clear, _ := EncodeBitOrWithProof(input, pubKey, nil, 0, 0)
	return cipher, clear
}

//EncodeBitOrWithProof computes the encoding of bit Xi, under the OR operation with range proofs
func EncodeBitOrWithProof(input bool, pubKey kyber.Point, sigs []libdrynx.PublishSignature, l int64, u int64) (*libunlynx.CipherText, int64, libdrynx.CreateProof) {
	cipher := libunlynx.CipherText{}
	toEncrypt := int64(0)
	cp := libdrynx.CreateProof{}
	if sigs != nil {
		if input {
			toEncrypt = int64(1)
		}
		tmp, r := libunlynx.EncryptIntGetR(pubKey, toEncrypt)
		cipher = *tmp
		//input range validation proof
		cp = libdrynx.CreateProof{Sigs: sigs, U: u, L: l, Secret: toEncrypt, R: r, CaPub: pubKey, Cipher: cipher}

	} else {
		randomScalar := libunlynx.SuiTe.Scalar().Zero()
		Zero := libunlynx.SuiTe.Scalar().Zero()
		if input == true {
			//generate random number using Scalar
			randomScalar = libunlynx.SuiTe.Scalar().Pick(random.New())
			//keep generating random numbers until we get a non-zero one
			for i := 0; i <= 10; i++ {
				if randomScalar == Zero {
					randomScalar = libunlynx.SuiTe.Scalar().Pick(random.New())
				} else {
					break
				}
			}
		}
		//encrypt the local representation of the bit
		cipher = *libunlynx.EncryptScalar(pubKey, randomScalar)
	}

	return &cipher, toEncrypt, cp
}

//DecodeBitOR computes the decoding of bit Xi, under the OR operation
func DecodeBitOR(result libunlynx.CipherText, secKey kyber.Scalar) bool {
	//decrypt the bit representation
	output := libunlynx.DecryptCheckZero(secKey, result)
	//as per our convention, if R > 0, then the corresponding bit is a 1, else it is a 0
	if output == int64(0) {
		return false
	}
	return true
}

//EncodeBitAND computes the encoding of bit Xi, under the AND operation
func EncodeBitAND(input bool, pubKey kyber.Point) (*libunlynx.CipherText, int64) {
	cipher, clear, _ := EncodeBitANDWithProof(input, pubKey, nil, 0, 0)
	return cipher, clear
}

//EncodeBitANDWithProof computes the encoding of bit Xi, under the AND operation with range proofs
func EncodeBitANDWithProof(input bool, pubKey kyber.Point, sigs []libdrynx.PublishSignature, l int64, u int64) (*libunlynx.CipherText, int64, libdrynx.CreateProof) {
	cipher := libunlynx.CipherText{}
	toEncrypt := int64(1)
	cp := libdrynx.CreateProof{}
	if sigs != nil {
		if input {
			toEncrypt = int64(0)
		}
		tmp, r := libunlynx.EncryptIntGetR(pubKey, toEncrypt)
		cipher = *tmp
		//input range validation proof
		cp = libdrynx.CreateProof{Sigs: sigs, U: u, L: l, Secret: toEncrypt, R: r, CaPub: pubKey, Cipher: cipher}

	} else {
		randomScalar := libunlynx.SuiTe.Scalar().Zero()
		Zero := libunlynx.SuiTe.Scalar().Zero()
		if input == false {
			//generate random number using Scalar
			randomScalar = libunlynx.SuiTe.Scalar().Pick(random.New())
			//keep generating random numbers until we get a non-zero one
			for i := 0; i <= 10; i++ {
				if randomScalar == Zero {
					randomScalar = libunlynx.SuiTe.Scalar().Pick(random.New())
				} else {
					break
				}
			}
		}
		//encrypt the local representation of the bit
		cipher = *libunlynx.EncryptScalar(pubKey, randomScalar)
	}

	return &cipher, toEncrypt, cp
}

//DecodeBitAND computes the decoding of bit Xi, under the AND operation
func DecodeBitAND(result libunlynx.CipherText, secKey kyber.Scalar) bool {
	//decrypt the bit representation
	output := libunlynx.DecryptCheckZero(secKey, result)
	//as per our convention, if R > 0, then the corresponding bit is a 1, else it is a 0
	if output == int64(0) {
		return true
	}
	return false
}

//LocalResultOR calculates the local result of the OR operation over all boolean values of the input array
func LocalResultOR(input []bool) bool {
	localResult := false
	for i := int64(0); i < int64(len(input)); i++ {
		if input[i] == true {
			localResult = true
			break
		}
	}
	return localResult
}

//LocalResultAND calculates the local result of the AND operation over all boolean values of the input array
func LocalResultAND(input []bool) bool {
	localResult := true
	for i := int64(0); i < int64(len(input)); i++ {
		if input[i] == false {
			localResult = false
			break
		}
	}
	return localResult
}
