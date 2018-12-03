package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShufflingProof(t *testing.T) {
	_, pubKey := libunlynx.GenKey()

	//create data
	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse
	mapi[1] = processResponse1
	mapi[2] = processResponse2
	mapi[3] = processResponse
	responsesShuffled, pi, beta := ShuffleSequence(mapi, nil, pubKey, nil)
	PublishedShufflingProof := ShufflingProofCreation(mapi, responsesShuffled, nil, pubKey, beta, pi)
	assert.True(t, ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = ShufflingProofCreation(mapi, mapi, nil, pubKey, beta, pi)
	assert.False(t, ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
