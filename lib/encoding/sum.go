package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib"
)

// EncodeSum computes the sum of query results
func EncodeSum(input []int64, pubKey kyber.Point) (*libunlynx.CipherText, []int64) {
	resultEnc, resultClear, _ := EncodeSumWithProofs(input, pubKey, nil, 0, 0)
	return resultEnc, resultClear
}

// EncodeSumWithProofs computes the sum of query results with the proof of range
func EncodeSumWithProofs(input []int64, pubKey kyber.Point, sigs []libdrynx.PublishSignature, l int64, u int64) (*libunlynx.CipherText, []int64, []libdrynx.CreateProof) {
	//sum the local DP's query results
	sum := int64(0)
	for _, el := range input {
		sum += el
	}
	//encrypt the local DP's query result
	sumEncrypted, r := libdrynx.EncryptIntGetR(pubKey, sum)

	if sigs == nil {
		return sumEncrypted, []int64{sum}, nil
	}
	//input range validation proof
	cp := libdrynx.CreateProof{Sigs: sigs, U: u, L: l, Secret: sum, R: r, CaPub: pubKey, Cipher: *sumEncrypted}

	return sumEncrypted, []int64{sum}, []libdrynx.CreateProof{cp}
}

// DecodeSum computes the sum of local DP's query results
func DecodeSum(result libunlynx.CipherText, secKey kyber.Scalar) int64 {
	//decrypt the query results
	return libunlynx.DecryptIntWithNeg(secKey, result)

}
