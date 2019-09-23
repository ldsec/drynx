package libdrynxencoding_test

import (
	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/encoding"
	"github.com/ldsec/drynx/lib/range"
	"github.com/ldsec/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3/log"
	"math"
	"testing"
)

func TestEncodeDecodeCosim(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	limit := int64(10000)
	log.Lvl1("Preparing decryption up to:", limit)

	// Decrpytion hashtable creation
	libunlynx.CreateDecryptionTable(limit, pubKey, secKey)

	//data
	rijs := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12}
	riks := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12}

	// excpected results
	rijsSum := int64(0)
	riksSum := int64(0)
	rijs2Sum := int64(0)
	riks2Sum := int64(0)
	rijsxRijksSum := int64(0)

	for i, el := range rijs {
		el2 := riks[i]
		rijsSum = rijsSum + el
		riksSum = riksSum + el2
		rijs2Sum = rijs2Sum + el*el
		riks2Sum = riks2Sum + el2*el2
		rijsxRijksSum = rijsxRijksSum + el*el2

	}
	resultClear := []int64{rijsSum, riksSum, rijs2Sum, riks2Sum, rijsxRijksSum}
	log.LLvl1("Preliminary Results ", resultClear)

	//expected results
	expect := float64(resultClear[4]) / (math.Sqrt(float64(resultClear[2])) * math.Sqrt(float64(resultClear[3])))
	log.Lvl1("Expected Preliminary Results ", resultClear)

	resultEncrypted, _ := libdrynxencoding.EncodeCosim(rijs, riks, pubKey)
	result := libdrynxencoding.DecodeCosim(resultEncrypted, secKey)
	log.LLvl1("Final Results ", result)
	assert.Equal(t, expect, result)
}

func TestEncodeDecodeCosimWithProofs(t *testing.T) {
	// key
	keys := key.NewKeyPair(libunlynx.SuiTe)
	secKey, pubKey := keys.Private, keys.Public

	limit := int64(10000)
	log.Lvl1("Preparing decryption up to:", limit)

	// Decrpytion hashtable creation
	libunlynx.CreateDecryptionTable(limit, pubKey, secKey)

	//data
	rijs := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1}
	riks := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1}

	// excpected results
	rijsSum := int64(0)
	riksSum := int64(0)
	rijs2Sum := int64(0)
	riks2Sum := int64(0)
	rijsXRijksSum := int64(0)

	for i, el := range rijs {
		el2 := riks[i]
		rijsSum = rijsSum + el
		riksSum = riksSum + el2
		rijs2Sum = rijs2Sum + el*el
		riks2Sum = riks2Sum + el2*el2
		rijsXRijksSum = rijsXRijksSum + el*el2

	}
	resultClear := []int64{rijsSum, riksSum, rijs2Sum, riks2Sum, rijsXRijksSum}

	//expected results
	expect := float64(resultClear[4]) / (math.Sqrt(float64(resultClear[2])) * math.Sqrt(float64(resultClear[3])))

	//proofs signatures
	//signatures needed to check the proof
	u := int64(2)
	l := int64(10)
	ps := make([][]libdrynx.PublishSignature, 2)

	ranges := make([]*[]int64, len(resultClear))
	ps[0] = make([]libdrynx.PublishSignature, len(resultClear))
	ps[1] = make([]libdrynx.PublishSignature, len(resultClear))
	ys := make([][]kyber.Point, 2)
	ys[0] = make([]kyber.Point, len(resultClear))
	ys[1] = make([]kyber.Point, len(resultClear))
	for i := range ps[0] {
		ps[0][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ps[1][i] = libdrynxrange.PublishSignatureBytesToPublishSignatures(libdrynxrange.InitRangeProofSignature(u))
		ys[0][i] = ps[0][i].Public
		ys[1][i] = ps[1][i].Public
		ranges[i] = &[]int64{u, l}
	}

	yss := make([][]kyber.Point, len(resultClear))
	for i := range yss {
		yss[i] = make([]kyber.Point, 2)
		for j := range ys {
			yss[i][j] = ys[j][i]
		}
	}

	resultEncrypted, _, prf := libdrynxencoding.EncodeCosimWithProofs(rijs, riks, pubKey, ps, ranges)
	for i, v := range prf {
		yss := make([]kyber.Point, 2)
		for j := range ys {
			yss[j] = ys[j][i]
		}
		assert.True(t, libdrynxrange.RangeProofVerification(libdrynxrange.CreatePredicateRangeProofForAllServ(v), u, l, yss, pubKey))
	}

	result := libdrynxencoding.DecodeCosim(resultEncrypted, secKey)
	assert.Equal(t, expect, result)
}
