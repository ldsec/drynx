package libdrynxencoding_test

import (
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/log"
	"testing"
)

//TestEncodeDecodeVariance tests EncodeVariance and DecodeVariance
func TestEncodeDecodeVariance(t *testing.T) {
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	limit := int64(10000)
	log.Lvl1("Preparing decryption up to:", limit)

	// Decrpytion hashtable creation
	libunlynx.CreateDecryptionTable(limit, pubKey, secKey)

	//data
	inputValues := []int64{0, 1, 2, -3, -44, 5, 6, -7, -8, 9, -120}

	//expected results
	sumSquares := int64(0)
	sum := int64(0)
	for _, el := range inputValues {
		sum += el
		sumSquares += el * el
	}
	N := int64(len(inputValues))
	mean := float64(sum) / float64(N)
	expect := float64(sumSquares)/float64(N) - mean*mean
	log.Lvl1(expect)
	//function call
	resultEncrypted, _ := libdrynxencoding.EncodeVariance(inputValues, pubKey)
	result := libdrynxencoding.DecodeVariance(resultEncrypted, secKey)

	assert.Equal(t, expect, result)
}

// TestEncodeDecodeVarianceWithProofs tests EncodeVariance and DecodeVariance with input range validation
func TestEncodeDecodeVarianceWithProofs(t *testing.T) {
	//data
	inputValues := []int64{0, 10, 9, 1, 11}

	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	limit := int64(10000)
	log.Lvl1("Preparing decryption up to:", limit)

	// Decrpytion hashtable creation
	libunlynx.CreateDecryptionTable(limit, pubKey, secKey)

	//expected results
	sum_squares := int64(0)
	sum := int64(0)
	for _, el := range inputValues {
		sum += el
		sum_squares += el * el
	}
	N := int64(len(inputValues))
	mean := float64(sum) / float64(N)
	expect := float64(sum_squares)/float64(N) - mean*mean

	//signatures needed to check the proof
	u := []int64{2, 2, 2}
	l := []int64{5, 3, 9}

	ranges := make([]*[]int64, 3)
	ps := make([][]libdrynx.PublishSignature, 2)
	ps[0] = make([]libdrynx.PublishSignature, 3)
	ps[1] = make([]libdrynx.PublishSignature, 3)
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, 3)
	ys[1] = make([]kyber.Point, 3)
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u[i]))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u[i], l[i]}
	}

	yss := make([][]kyber.Point, 3)
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	//function call
	resultEncrypted, _, prf := libdrynxencoding.EncodeVarianceWithProofs(inputValues, pubKey, ps, ranges)
	result := libdrynxencoding.DecodeVariance(resultEncrypted, secKey)

	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[0]), u[0], l[0], yss[0], pubKey))
	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[1]), u[1], l[1], yss[1], pubKey))
	assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(prf[2]), u[2], l[2], yss[2], pubKey))
	assert.Equal(t, expect, result)
}
