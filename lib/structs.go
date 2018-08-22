package lib

import (
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/skip"
	"time"
)

// QueryInfo is a structure used in the service to store information about a query in the concurrent map.
// This information helps us to know how many proofs have been received and processed.
type QueryInfo struct {
	Bitmap         map[string]int64
	TotalNbrProofs []int
	Query          *SurveyQuery

	// channels
	SharedBMChannel            chan map[string]int64
	SharedBMChannelToTerminate chan struct{}
	EndVerificationChannel     chan skipchain.SkipBlock // To wait for the verifying nodes to finish all the verifications
}

// Reply is the response struct for all API calls to the skipchain service
type Reply struct {
	Latest *skipchain.SkipBlock
}

// GetLatestBlock is the message used to fetch the last block from a skipchain
type GetLatestBlock struct {
	Roster *onet.Roster
	Sb     *skipchain.SkipBlock
}

// GetProofs is a request to get the proofs from a server, from query with SurveyID given as parameter
type GetProofs struct {
	ID string
}

//ProofsAsMap is the reply from the Service containing a map as protobuf expect a return struct
type ProofsAsMap struct {
	Proofs map[string][]byte
}

type CloseDB struct {
	Close int64
}

type GetGenesis struct {
}

type GetBlock struct {
	Roster *onet.Roster
	ID     string
}

//Data for Test Below
//--------------------------------------------------------------------------------------------------------------------------------------------------

//Some variables to create dataTest
var secKey = libunlynx.SuiTe.Scalar().Pick(random.New())
var entityPub = libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
var tab1 = []int64{1, 2, 3, 6}
var tab2 = []int64{2, 4, 8, 6}

//CreateRandomGoodTestData only creates valid proofs
func CreateRandomGoodTestData(roster *onet.Roster, pub kyber.Point, ps []*[]libunlynx.PublishSignatureBytes, ranges []*[]int64, nbrProofs int) skip.DataToVerify {
	//var cipherOne = *libunlynx.EncryptInt(roster.Aggregate, 10)

	result := skip.DataToVerify{}
	result.ProofsKeySwitch = make([]*libunlynx.PublishedKSListProof, nbrProofs)
	result.ProofsRange = make([]*libunlynx.RangeProofList, nbrProofs)
	result.ProofsAggregation = make([]*libunlynx.PublishAggregationProof, nbrProofs)
	result.ProofsObfuscation = make([]*libunlynx.PublishedListObfuscationProof, nbrProofs)
	result.ProofShuffle = make([]*libunlynx.PublishedShufflingProof, nbrProofs)

	//Fill Aggregation with good proofs

	for i := range result.ProofsAggregation {
		tab := []int64{1, 2, 3, 4, 5}
		ev := libunlynx.EncryptIntVector(roster.Aggregate, tab)

		dpResponse1 := libunlynx.ResponseDPOneGroup{Group: "1", Data: *ev}
		dpResponse2 := libunlynx.ResponseDPOneGroup{Group: "2", Data: *ev}
		evresult := libunlynx.NewCipherVector(len(*ev))
		evresult.Add(*ev, *ev)
		dpResponseResult1 := libunlynx.ResponseDPOneGroup{Group: "1", Data: *evresult}
		dpResponseResult2 := libunlynx.ResponseDPOneGroup{Group: "2", Data: *evresult}
		dpAggregated := libunlynx.ResponseAllDPs{Data: []libunlynx.ResponseDPOneGroup{dpResponseResult1, dpResponseResult2}}
		dpResponses := libunlynx.ResponseAllDPs{Data: []libunlynx.ResponseDPOneGroup{dpResponse1, dpResponse1, dpResponse2, dpResponse2}}
		proof := libunlynx.ServerAggregationProofCreation(dpResponses, dpAggregated)
		result.ProofsAggregation[i] = &proof
	}

	for i := range result.ProofsObfuscation {
		tab := []int64{1, 2}
		e := libunlynx.EncryptIntVector(roster.Aggregate, tab)
		obfFactor := libunlynx.SuiTe.Scalar().Pick(random.New())
		newE1 := libunlynx.CipherText{}
		newE1.MulCipherTextbyScalar((*e)[0], obfFactor)
		newE2 := libunlynx.CipherText{}
		newE2.MulCipherTextbyScalar((*e)[1], obfFactor)
		proof := libunlynx.ObfuscationListProofCreation(*e, libunlynx.CipherVector{newE1, newE2}, []kyber.Scalar{obfFactor, obfFactor})
		result.ProofsObfuscation[i] = &proof
	}

	for i := range result.ProofShuffle {
		testCipherVect1 := *libunlynx.EncryptIntVector(roster.Aggregate, tab1)

		testCipherVect2 := *libunlynx.EncryptIntVector(roster.Aggregate, tab2)

		responses := make([]libunlynx.ProcessResponse, 3)
		responses[0] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
		responses[1] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
		responses[2] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

		responsesShuffled, pi, beta := libunlynx.ShuffleSequence(responses, libunlynx.SuiTe.Point().Base(), roster.Aggregate, nil)
		prf := libunlynx.ShufflingProofCreation(responses, responsesShuffled, libunlynx.SuiTe.Point().Base(), roster.Aggregate, beta, pi)
		result.ProofShuffle[i] = &prf
	}

	for i := range result.ProofsKeySwitch {
		length := 2
		cipher := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 2})
		initialTab := make([]kyber.Point, 2)
		for i, v := range *cipher {
			initialTab[i] = v.K
		}

		switchedVect := libunlynx.NewCipherVector(length)
		ks2s, rBNegs, vis := switchedVect.NewKeySwitching(pub, initialTab, secKey)

		pkslp := libunlynx.KeySwitchListProofCreation(entityPub, pub, secKey, length, ks2s, rBNegs, vis)

		result.ProofsKeySwitch[i] = &pkslp
	}

	for i := range result.ProofsRange {

		encryption, r := libunlynx.EncryptIntGetR(roster.Aggregate, int64(25))

		// read the signatures needed to compute the range proofs
		signatures := make([][]libunlynx.PublishSignature, len(roster.List))
		for i := 0; i < len(roster.List); i++ {
			signatures[i] = make([]libunlynx.PublishSignature, len(ranges))
			for j := 0; j < len(ranges); j++ {
				signatures[i][j] = libunlynx.PublishSignatureBytesToPublishSignatures((*ps[i])[j])
			}
		}

		cp := libunlynx.CreateProof{Sigs: libunlynx.ReadColumn(signatures, 0), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cp1 := libunlynx.CreateProof{Sigs: libunlynx.ReadColumn(signatures, 1), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cps := []libunlynx.CreateProof{cp, cp1}
		rps := libunlynx.RangeProofList{Data: libunlynx.CreatePredicateRangeProofListForAllServers(cps)}
		result.ProofsRange[i] = &rps
	}

	return result
}

//DataToVerify contains the proofs to be verified by the skipchain CA
type DataToVerify struct {
	ProofsRange       []*libunlynx.RangeProofList
	ProofsAggregation []*libunlynx.PublishAggregationProof
	ProofsObfuscation []*libunlynx.PublishedListObfuscationProof
	ProofsKeySwitch   []*libunlynx.PublishedKSListProof
	ProofShuffle      []*libunlynx.PublishedShufflingProof
}

//PublishRangeProofByte is structure to send with array of point as byte as it cannot be converted
/*type PublishRangeProofByte struct {
	Commit    libunlynx.CipherText
	Challenge kyber.Scalar
	Zr        kyber.Scalar
	D         kyber.Point
	Zv        []kyber.Scalar
	Zphi      []kyber.Scalar
	V         [][]byte
	A         [][]byte
}*/

//VerifRangProof is to verify a Range proof coming from a DP. A server need to give range,
//but also the public key and P CA key that was used to encode the data
/*type VerifRangeProof struct {
	Proof *PublishRangeProofByte
	U     int64
	L     int64
	Y     []kyber.Point
	P     kyber.Point
}*/

//VerifyShufllingProof contains the proof and Seed needed to bverify them
/*type VerifyShufflingProof struct {
	Proof libunlynx.PublishedShufflingProof
	Seed  kyber.Point
}*/

//PublishedCollectiveAggregationProofByte is the PublishedCollectiveAggregationProof friendly to protobuff,
//meaning you transform field that cannot be transfered throught protobuf, to bytes
/*type PublishedCollectiveAggregationProofByte struct {
	Aggregation1      map[libunlynx.GroupingKey][]byte
	Size11            []int64
	Size12            []int64
	Aggregation2      []libunlynx.FilteredResponseDet
	AggregationResult map[libunlynx.GroupingKey][]byte
	Size21            []int64
	Size22            []int64
}*/

//DataBlock is the structure inserted in the Skipchain
type DataBlock struct {
	Roster       *onet.Roster
	SurveyID     string
	Sample       float64
	Time         time.Time
	ServerNumber int64
	Proofs       map[string]int64
}

//BitMap is used to send a structure containing a map in protobuf. You cannot send a map as protobuf
//expect a pointer on structure
type BitMap struct {
	BitMap map[string]int64
}

const PROOF_FALSE = int64(0)
const PROOF_TRUE = int64(1)
const PROOF_RECEIVED = int64(2)
const PROOF_NOT_RECEIVED = int64(3)
const PROOF_FALSE_SIGN = int64(4)


// ResponseDP will contain the data to be sent to the server.
type ResponseDPOneGroup struct {
	Group string
	Data  libunlynx.CipherVector
}

// ResponseDP will contain the data to be sent to the server.
type ResponseDPOneGroupBytes struct {
	Groups   []byte
	Data     []byte
	CVLength []byte
}

// ResponseDP will contain the data to be sent to the server.
type ResponseAllDPs struct {
	Data []ResponseDPOneGroup
}

// ResponseDP will contain the data to be sent to the server.
type ResponseAllDPsBytes struct {
	Data []ResponseDPOneGroupBytes
}

// ResponseDP will contain the data to be sent to the server.
type ResponseDPBytes struct {
	Data map[string][]byte
	Len  int
}

// CothorityAggregatedData is the collective aggregation result.
type CothorityAggregatedData struct {
	GroupedData map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

func (rdog *ResponseDPOneGroup) ToBytes() ResponseDPOneGroupBytes {
	result := ResponseDPOneGroupBytes{}
	result.Groups = []byte(rdog.Group)
	tmp, leng := rdog.Data.ToBytes()
	result.Data = tmp
	result.CVLength = []byte{byte(leng)}

	return result
}

func (rdog *ResponseDPOneGroup) FromBytes(rdogb ResponseDPOneGroupBytes) {
	tmp := libunlynx.NewCipherVector(int(rdogb.CVLength[0]))
	tmp.FromBytes(rdogb.Data, int(rdogb.CVLength[0]))
	rdog.Data = *tmp
	rdog.Group = string(rdogb.Groups)
}

func (rad *ResponseAllDPs) ToBytes() ResponseAllDPsBytes {
	result := ResponseAllDPsBytes{}
	result.Data = make([]ResponseDPOneGroupBytes, len(rad.Data))
	wg := libunlynx.StartParallelize(len(rad.Data))
	for i, v := range rad.Data {
		go func(i int, v ResponseDPOneGroup) {
			defer wg.Done()
			result.Data[i] = v.ToBytes()
		}(i, v)
	}
	libunlynx.EndParallelize(wg)
	return result
}

func (rad *ResponseAllDPs) FromBytes(radb ResponseAllDPsBytes) {
	rad.Data = make([]ResponseDPOneGroup, len(radb.Data))
	wg := libunlynx.StartParallelize(len(radb.Data))
	for i, v := range radb.Data {
		go func(i int, v ResponseDPOneGroupBytes) {
			defer wg.Done()
			rad.Data[i].FromBytes(v)
		}(i, v)

	}
	libunlynx.EndParallelize(wg)
}