package libdrynx

import (
	"github.com/coreos/bbolt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"sync"
	"time"
)

const proofFalse = int64(0)

// ProofTrue is the constant used to indicate that a proof is true in the bitmap
const ProofTrue = int64(1)
const proofReceived = int64(2)
const proofFalseSign = int64(4)

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

// ProofsAsMap is the reply from the Service containing a map as protobuf expect a return struct
type ProofsAsMap struct {
	Proofs map[string][]byte
}

// CloseDB is the struct to close a DB
type CloseDB struct {
	Close int64
}

// GetGenesis is the struct used to trigger the fetching of the genesis block
type GetGenesis struct {
}

// GetBlock is used to fetch a block
type GetBlock struct {
	Roster *onet.Roster
	ID     string
}

// DataToVerify contains the proofs to be verified by the skipchain CA
type DataToVerify struct {
	ProofsRange       []*RangeProofList
	ProofsAggregation []*PublishAggregationProof
	ProofsObfuscation []*PublishedListObfuscationProof
	ProofsKeySwitch   []*PublishedKSListProof
	ProofShuffle      []*PublishedShufflingProof
}

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

// ResponseDPOneGroup contain the data to be sent to the server.
type ResponseDPOneGroup struct {
	Group string
	Data  libunlynx.CipherVector
}

// ResponseDPOneGroupBytes contain DP answers in bytes
type ResponseDPOneGroupBytes struct {
	Groups   []byte
	Data     []byte
	CVLength []byte
}

// ResponseAllDPs contain list of DPs answers.
type ResponseAllDPs struct {
	Data []ResponseDPOneGroup
}

// ResponseAllDPsBytes will contain the data to be sent to the server.
type ResponseAllDPsBytes struct {
	Data []ResponseDPOneGroupBytes
}

// ResponseDPBytes contains DP answers in bytes.
type ResponseDPBytes struct {
	Data map[string][]byte
	Len  int
}

// CothorityAggregatedData is the collective aggregation result.
type CothorityAggregatedData struct {
	GroupedData map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// WhereQueryAttributeClear is the name and value of a where attribute in the query
type WhereQueryAttributeClear struct {
	Name  string
	Value string
}

// ShufflingMessage represents a message containing data to shuffle
type ShufflingMessage struct {
	Data []libunlynx.ProcessResponse
}

// ShufflingBytesMessage represents a shuffling message in bytes
type ShufflingBytesMessage struct {
	Data *[]byte
}

// ResponseDP contains the data provider's response to be sent to the server.
type ResponseDP struct {
	Data map[string]libunlynx.CipherVector // group -> value(s)
}

//PublishSignature contains points signed with a private key and the public key associated to verify the signatures.
type PublishSignature struct {
	Public    kyber.Point   // y
	Signature []kyber.Point // A_i
}

//PublishSignatureBytes is the same as PublishSignature but the signatures are in bytes
type PublishSignatureBytes struct { //need this because of G2 in protobuf not working
	Public    kyber.Point // y
	Signature []byte      // A_i
}

// QueryDiffP contains diffP parameters for a query
type QueryDiffP struct {
	LapMean       float64
	LapScale      float64
	NoiseListSize int
	Quanta        float64
	Scale         float64
	Limit         float64
}

// QueryDPDataGen contains the query information for the generation of data at DP
type QueryDPDataGen struct {
	GroupByValues   []int64 // the number of groups = len(GroupByValues); number of categories for each group GroupByValues[i]
	GenerateRows    int64
	GenerateDataMin int64
	GenerateDataMax int64
}

// QueryIVSigs contains parameters for input validation
type QueryIVSigs struct {
	InputValidationSigs  []*[]PublishSignatureBytes
	InputValidationSize1 int
	InputValidationSize2 int
}

// QuerySQL contains SQL parameters of the query
type QuerySQL struct {
	Select    []string
	Where     []WhereQueryAttributeClear
	Predicate string
	GroupBy   []string
}

// Query is used to transport query information through servers, to DPs
type Query struct {
	// query statement
	Operation   Operation
	Ranges      []*[]int64
	Proofs      int
	Obfuscation bool
	DiffP       QueryDiffP

	// define how the DPs generate dummy data
	DPDataGen QueryDPDataGen

	// identity skipchain simulation
	IVSigs    QueryIVSigs
	RosterVNs *onet.Roster

	// if real DB at data providers
	SQL QuerySQL

	//simulation
	CuttingFactor int
}

// Operation defines the operation in the query
type Operation struct {
	NameOp       string
	NbrInput     int
	NbrOutput    int
	QueryMin     int64
	QueryMax     int64
	LRParameters LogisticRegressionParameters
}

// LogisticRegressionParameters are the parameters specific to logistic regression
type LogisticRegressionParameters struct {
	// logistic regression specific
	FilePath           string
	NbrRecords         int64
	NbrFeatures        int64
	Means              []float64
	StandardDeviations []float64

	// parameters
	Lambda         float64
	Step           float64
	MaxIterations  int
	InitialWeights []float64

	// approximation
	K                           int
	PrecisionApproxCoefficients float64
}

// SurveyQuery is the complete query
type SurveyQuery struct {
	SurveyID      string
	RosterServers onet.Roster
	ClientPubKey  kyber.Point
	IntraMessage  bool // to define whether the query was sent by the querier or not
	ServerToDP    map[string]*[]network.ServerIdentity
	// query statement
	Query Query
	//map of DP/Server to Public key
	IDtoPublic map[string]kyber.Point
	//Threshold for verification in skipChain service
	Threshold                  float64
	ObfuscationProofThreshold  float64
	RangeProofThreshold        float64
	KeySwitchingProofThreshold float64
}

// SurveyQueryToVN is the version of the query sent to the VNs
type SurveyQueryToVN struct {
	SQ SurveyQuery
}

// SurveyQueryToDP is the version of the query for the DPs
type SurveyQueryToDP struct {
	SQ   SurveyQuery
	Root *network.ServerIdentity
}

// EndVerificationRequest is the request to wait until the end of the proofs' verification
type EndVerificationRequest struct {
	QueryInfoID string
}

// EndVerificationResponse is the response to a waiting on the vend of the verification
type EndVerificationResponse struct{}

//Data for Test Below
//--------------------------------------------------------------------------------------------------------------------------------------------------
//Some variables to create dataTest
var secKey = bn256.NewSuiteG1().Scalar().Pick(random.New())
var entityPub = bn256.NewSuiteG1().Point().Mul(secKey, bn256.NewSuiteG1().Point().Base())
var tab1 = []int64{1, 2, 3, 6}
var tab2 = []int64{2, 4, 8, 6}

//CreateRandomGoodTestData only creates valid proofs
func CreateRandomGoodTestData(roster *onet.Roster, pub kyber.Point, ps []*[]PublishSignatureBytes, ranges []*[]int64, nbrProofs int) DataToVerify {
	result := DataToVerify{}
	result.ProofsKeySwitch = make([]*PublishedKSListProof, nbrProofs)
	result.ProofsRange = make([]*RangeProofList, nbrProofs)
	result.ProofsAggregation = make([]*PublishAggregationProof, nbrProofs)
	result.ProofsObfuscation = make([]*PublishedListObfuscationProof, nbrProofs)
	result.ProofShuffle = make([]*PublishedShufflingProof, nbrProofs)

	//Fill Aggregation with good proofs
	for i := range result.ProofsAggregation {
		tab := []int64{1, 2, 3, 4, 5}
		ev := libunlynx.EncryptIntVector(roster.Aggregate, tab)

		dpResponse1 := ResponseDPOneGroup{Group: "1", Data: *ev}
		dpResponse2 := ResponseDPOneGroup{Group: "2", Data: *ev}
		evresult := libunlynx.NewCipherVector(len(*ev))
		evresult.Add(*ev, *ev)
		dpResponseResult1 := ResponseDPOneGroup{Group: "1", Data: *evresult}
		dpResponseResult2 := ResponseDPOneGroup{Group: "2", Data: *evresult}
		dpAggregated := ResponseAllDPs{Data: []ResponseDPOneGroup{dpResponseResult1, dpResponseResult2}}
		dpResponses := ResponseAllDPs{Data: []ResponseDPOneGroup{dpResponse1, dpResponse1, dpResponse2, dpResponse2}}
		proof := ServerAggregationProofCreation(dpResponses, dpAggregated)
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
		proof := ObfuscationListProofCreation(*e, libunlynx.CipherVector{newE1, newE2}, []kyber.Scalar{obfFactor, obfFactor})
		result.ProofsObfuscation[i] = &proof
	}

	for i := range result.ProofShuffle {
		testCipherVect1 := *libunlynx.EncryptIntVector(roster.Aggregate, tab1)

		testCipherVect2 := *libunlynx.EncryptIntVector(roster.Aggregate, tab2)

		responses := make([]libunlynx.ProcessResponse, 3)
		responses[0] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
		responses[1] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
		responses[2] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

		responsesShuffled, pi, beta := ShuffleSequence(responses, libunlynx.SuiTe.Point().Base(), roster.Aggregate, nil)
		prf := ShufflingProofCreation(responses, responsesShuffled, libunlynx.SuiTe.Point().Base(), roster.Aggregate, beta, pi)
		result.ProofShuffle[i] = &prf
	}

	for i := range result.ProofsKeySwitch {
		length := 2
		cipher := libunlynx.EncryptIntVector(roster.Aggregate, []int64{1, 2})
		initialTab := make([]kyber.Point, 2)
		for i, v := range *cipher {
			initialTab[i] = v.K
		}

		//switchedVect := libunlynx.NewCipherVector(length)
		_, ks2s, rBNegs, vis := NewKeySwitching(pub, initialTab, secKey)

		pkslp := KeySwitchListProofCreation(entityPub, pub, secKey, length, ks2s, rBNegs, vis)

		result.ProofsKeySwitch[i] = &pkslp
	}

	for i := range result.ProofsRange {

		encryption, r := libunlynx.EncryptIntGetR(roster.Aggregate, int64(25))

		// read the signatures needed to compute the range proofs
		signatures := make([][]PublishSignature, len(roster.List))
		for i := 0; i < len(roster.List); i++ {
			signatures[i] = make([]PublishSignature, len(ranges))
			for j := 0; j < len(ranges); j++ {
				signatures[i][j] = PublishSignatureBytesToPublishSignatures((*ps[i])[j])
			}
		}

		cp := CreateProof{Sigs: ReadColumn(signatures, 0), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cp1 := CreateProof{Sigs: ReadColumn(signatures, 1), U: 16, L: 16, Secret: int64(25), R: r, CaPub: roster.Aggregate, Cipher: *encryption}
		cps := []CreateProof{cp, cp1}
		rps := RangeProofList{Data: CreatePredicateRangeProofListForAllServers(cps)}
		result.ProofsRange[i] = &rps
	}

	return result
}

// ToBytes transforms ResponseDPOneGroup to bytes
func (rdog *ResponseDPOneGroup) ToBytes() ResponseDPOneGroupBytes {
	result := ResponseDPOneGroupBytes{}
	result.Groups = []byte(rdog.Group)
	tmp, leng := rdog.Data.ToBytes()
	result.Data = tmp
	result.CVLength = []byte{byte(leng)}

	return result
}

// FromBytes creates a ResponseDPOneGroup struct back from the bytes
func (rdog *ResponseDPOneGroup) FromBytes(rdogb ResponseDPOneGroupBytes) {
	tmp := libunlynx.NewCipherVector(int(rdogb.CVLength[0]))
	tmp.FromBytes(rdogb.Data, int(rdogb.CVLength[0]))
	rdog.Data = *tmp
	rdog.Group = string(rdogb.Groups)
}

// ToBytes transforms ResponseAllDPs to bytes
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

// FromBytes construct the ResponseAllDPs struct back from the bytes
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

// ConvertToAggregationStruct transforms ResponseAllDPs to a map
func ConvertToAggregationStruct(dp ResponseAllDPs) map[libunlynx.GroupingKey]libunlynx.FilteredResponse {
	convertedData := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, val := range dp.Data {
		tmpCv := libunlynx.NewCipherVector(len(val.Data))
		if _, ok := convertedData[libunlynx.GroupingKey(val.Group)]; ok {
			tmpCv.Add(convertedData[libunlynx.GroupingKey(val.Group)].AggregatingAttributes, val.Data)
		} else {
			tmpCv = &val.Data
		}
		convertedData[libunlynx.GroupingKey(val.Group)] = libunlynx.FilteredResponse{AggregatingAttributes: *tmpCv}
	}
	return convertedData
}

// ConvertFromAggregationStruct transforms CothorityAggregatedData to ResponseAllDPs
func ConvertFromAggregationStruct(cad CothorityAggregatedData) *ResponseAllDPs {
	response := make([]ResponseDPOneGroup, 0)
	for k, v := range cad.GroupedData {
		response = append(response, ResponseDPOneGroup{Group: string(k), Data: v.AggregatingAttributes})
	}

	return &ResponseAllDPs{response}
}

// ToBytes converts a ShufflingMessage to a byte array
func (sm *ShufflingMessage) ToBytes() (*[]byte, int, int, int) {
	b := make([]byte, 0)
	bb := make([][]byte, len((*sm).Data))

	var gacbLength int
	var aabLength int
	var pgaebLength int

	wg := libunlynx.StartParallelize(len((*sm).Data))
	var mutexD sync.Mutex
	for i := range (*sm).Data {
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexD.Lock()
				data := (*sm).Data[i]
				mutexD.Unlock()

				aux, gacbAux, aabAux, pgaebAux := data.ToBytes()

				mutexD.Lock()
				bb[i] = aux
				gacbLength = gacbAux
				aabLength = aabAux
				pgaebLength = pgaebAux
				mutexD.Unlock()
			}(i)
		} else {
			bb[i], gacbLength, aabLength, pgaebLength = (*sm).Data[i].ToBytes()
		}

	}
	libunlynx.EndParallelize(wg)

	for _, el := range bb {
		b = append(b, el...)
	}

	return &b, gacbLength, aabLength, pgaebLength
}

// FromBytes converts a byte array to a ShufflingMessage. Note that you need to create the (empty) object beforehand.
func (sm *ShufflingMessage) FromBytes(data *[]byte, gacbLength, aabLength, pgaebLength int) {
	var nbrData int
	cipherLength := libunlynx.SuiTe.PointLen() * 2
	elementLength := (gacbLength*cipherLength + aabLength*cipherLength + pgaebLength*cipherLength) //CAUTION: hardcoded 64 (size of el-gamal element C,K)
	if elementLength != 0 {

		nbrData = len(*data) / elementLength

		(*sm).Data = make([]libunlynx.ProcessResponse, nbrData)
		wg := libunlynx.StartParallelize(nbrData)
		for i := 0; i < nbrData; i++ {
			v := (*data)[i*elementLength : i*elementLength+elementLength]
			if libunlynx.PARALLELIZE {
				go func(v []byte, i int) {
					defer wg.Done()
					(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
				}(v, i)
			} else {
				(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
			}

		}
		libunlynx.EndParallelize(wg)
	}
}

// AddDiffP checks if differential privacy is required or not
func AddDiffP(qdf QueryDiffP) bool {
	return !(qdf.LapMean == 0.0 && qdf.LapScale == 0.0 && qdf.NoiseListSize == 0 && qdf.Quanta == 0.0 && qdf.Scale == 0 && qdf.Limit == 0)
}

func checkRangesZeros(ranges []*[]int64) bool {
	for _, v := range ranges {
		if (*v)[0] != int64(0) || (*v)[1] != int64(0) {
			return false
		}
	}
	return true
}

func checkRangesBits(ranges []*[]int64) bool {
	for _, v := range ranges {
		if (*v)[0] != int64(2) || (*v)[1] != int64(1) {
			return false
		}
	}
	return true
}

// CheckParameters checks that the query parameters make sens
func CheckParameters(sq SurveyQuery, diffP bool) bool {
	message := ""
	result := true
	if sq.Query.Proofs == 1 {
		if sq.Query.Obfuscation {
			if sq.ObfuscationProofThreshold == 0 {
				result = false
				message = message + "obfuscation threshold is 0 while obfuscation is true \n"
			}
			if sq.Query.Operation.NameOp != "bool_AND" && sq.Query.Operation.NameOp != "bool_OR" && sq.Query.Operation.NameOp != "min" && sq.Query.Operation.NameOp != "max" && sq.Query.Operation.NameOp != "union" && sq.Query.Operation.NameOp != "inter" {
				result = false
				message = message + "obfuscation threshold for a non accepted operation \n"
			}
			if !checkRangesBits(sq.Query.Ranges) {
				result = false
				message = message + "obfuscation and proofs but ranges not for 0,1 \n"
			}
		} else {
			if sq.ObfuscationProofThreshold != 0 {
				result = false
				message = message + "obfuscation threshold is set and there is no Obfuscation \n"
			}
		}
		if sq.Query.Ranges == nil {
			result = false
			message = message + "proofs but no range \n"
		}

		if sq.Query.IVSigs.InputValidationSigs == nil && !checkRangesZeros(sq.Query.Ranges) {
			result = false
			message = message + "proofs but no signatures \n"
		}

		if checkRangesZeros(sq.Query.Ranges) && sq.Query.IVSigs.InputValidationSigs != nil {
			result = false
			message = message + "ranges to 0 but signatures also set \n"
		}

		if sq.Query.IVSigs.InputValidationSigs != nil && sq.Query.Ranges != nil {
			if sq.Query.Operation.NbrOutput != len(*sq.Query.IVSigs.InputValidationSigs[0]) || sq.Query.Operation.NbrOutput != len(sq.Query.Ranges) {
				result = false
				message = message + "ranges or signatures length do not match with nbr output \n"
			}
		}
	} else if sq.Query.Proofs == 0 {

		if sq.KeySwitchingProofThreshold != 0 || sq.ObfuscationProofThreshold != 0 || sq.RangeProofThreshold != 0 || sq.Threshold != 0 {
			result = false
			message = message + "no proofs and one of the threshold not 0 \n"
		}

		if sq.Query.Ranges != nil || sq.Query.IVSigs.InputValidationSigs != nil {
			result = false
			message = message + "no proofs and some ranges or signatures \n"
		}

		if sq.Query.RosterVNs != nil {
			result = false
			message = message + "no proofs but VN roster \n"
		}

	} else {
		result = false
		message = message + "unsupported proof type \n"
	}

	if !diffP {
		if sq.Query.DiffP.Limit != 0.0 || sq.Query.DiffP.Scale != 0.0 || sq.Query.DiffP.Quanta != 0.0 || sq.Query.DiffP.NoiseListSize != 0 || sq.Query.DiffP.LapMean != 0 || sq.Query.DiffP.LapScale != 0.0 {
			result = false
			message = message + "no diffP but parameters not to 0 \n"
		}
	} else {
		if sq.Query.DiffP.Limit == 0.0 && sq.Query.DiffP.Quanta == 0.0 || sq.Query.DiffP.Scale == 0.0 || sq.Query.DiffP.NoiseListSize == 0 || sq.Query.DiffP.LapScale == 0.0 {
			result = false
			message = message + "diffP but parameters are 0 \n"
		}
	}

	if sq.Query.Operation.QueryMin != sq.Query.DPDataGen.GenerateDataMin || sq.Query.Operation.QueryMax != sq.Query.DPDataGen.GenerateDataMax {
		result = false
		message = message + "min or max are inconsistent at DP and operations \n"
	}

	if message != "" {
		log.LLvl1(message)
	}
	return result
}

// QueryToProofsNbrs creates the number of required proofs from the query parameters
func QueryToProofsNbrs(q SurveyQuery) []int {
	nbrDPs := 0

	for _, v := range q.ServerToDP {
		if v != nil {
			nbrDPs = nbrDPs + len(*v)
		}
	}
	nbrServers := len(q.RosterServers.List)

	// range proofs
	prfRange := nbrDPs
	// aggregation
	if q.Query.Proofs == 0 {
		nbrServers = 0
	}

	prfAggr := nbrServers
	prfObf := 0
	if q.Query.Obfuscation {
		prfObf = nbrServers
	}

	// differential privacy
	prfShuffling := 0
	if AddDiffP(q.Query.DiffP) {
		prfShuffling = nbrServers
	}

	// key switching
	prfKS := nbrServers
	return []int{prfRange, prfShuffling, prfAggr, prfObf, prfKS}
}

// UpdateDB put in a given bucket the value as byte with given key.
func UpdateDB(db *bolt.DB, bucketName string, key string, value []byte) {
	if err := db.Batch(func(tx *bolt.Tx) error {
		//Bucket with SurveyID server Adress
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			log.Fatal("error")
		}
		//Put at key previous block index, the bitmap
		err = b.Put([]byte(key), value)
		if err != nil {
			log.Fatal("error insert")
		}

		return nil
	}); err != nil {
		log.Fatal("Could not update DB", err)
	}
}

// ChooseOperation sets the parameters according to the operation
func ChooseOperation(operationName string, queryMin, queryMax, d int, cuttingFactor int) Operation {
	operation := Operation{}

	operation.NameOp = operationName
	operation.NbrInput = 0
	operation.NbrOutput = 0
	operation.QueryMax = int64(queryMax)
	operation.QueryMin = int64(queryMin)

	switch operationName {
	case "sum":
		operation.NbrInput = 1
		operation.NbrOutput = 1
		break
	case "mean":
		operation.NbrInput = 1
		operation.NbrOutput = 2
		break
	case "variance":
		operation.NbrInput = 1
		operation.NbrOutput = 3
		break
	case "cosim":
		operation.NbrInput = 2
		operation.NbrOutput = 5
		break
	case "frequencyCount", "min", "max", "union", "inter":
		//NbrOutput should be equal to (QueryMax - QueryMin + 1)
		operation.NbrInput = 1
		operation.NbrOutput = queryMax - queryMin + 1
		break
	case "bool_OR", "bool_AND":
		operation.NbrInput = 1
		operation.NbrOutput = 1
		break
	case "lin_reg":
		//NbrInput should be equal to d + 1, in the case of linear regression
		operation.NbrInput = d + 1
		operation.NbrOutput = (d*d + 5*d + 4) / 2
		break
	case "logistic regression":
		break
	default:
		log.Fatal("Operation: <", operation, "> does not exist")
	}

	if cuttingFactor != 0 {
		operation.NbrOutput = operation.NbrOutput * cuttingFactor
	}

	return operation
}
