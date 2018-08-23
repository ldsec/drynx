package lib

import (
	"github.com/coreos/bbolt"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
)

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


type QueryDiffP struct {
	LapMean       float64
	LapScale      float64
	NoiseListSize int
	Quanta        float64
	Scale         float64
	Limit         float64
}

func AddDiffP(qdf QueryDiffP) bool {
	return !(qdf.LapMean == 0.0 && qdf.LapScale == 0.0 && qdf.NoiseListSize == 0 && qdf.Quanta == 0.0 && qdf.Scale == 0 && qdf.Limit == 0)
}

type QueryDPDataGen struct {
	GroupByValues   []int64 // the number of groups = len(GroupByValues); number of categories for each group GroupByValues[i]
	GenerateRows    int64
	GenerateDataMin int64
	GenerateDataMax int64
}

type QueryIVSigs struct {
	InputValidationSigs  []*[]PublishSignatureBytes
	InputValidationSize1 int
	InputValidationSize2 int
}

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

type Operation struct {
	NameOp       string
	NbrInput     int
	NbrOutput    int
	QueryMin     int64
	QueryMax     int64
	LRParameters LogisticRegressionParameters
}

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

func CheckParameters(sq SurveyQuery, diffP bool) bool {
	message := ""
	result := true
	if sq.Query.Proofs == 1 {
		/*if sq.Threshold == 0 {
			result = false
			message = message + "threshold is 0 \n"
		}*/
		/*if sq.KeySwitchingProofThreshold == 0 {
			result = false
			message = message + "key switching threshold is 0 \n"
		}*/
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
		/*if sq.RangeProofThreshold == 0 {
			result = false
			message = message + "range proof Threshold is 0 and there are proofs \n"
		}*/
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

type SurveyQueryToVN struct {
	SQ SurveyQuery
}

type SurveyQueryToDP struct {
	SQ   SurveyQuery
	Root *network.ServerIdentity
}

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

type EndVerificationRequest struct {
	QueryInfoID string
}

type EndVerificationResponse struct{}

//updateDB put in a given bucket the value as byte with given key.
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
	default:
		log.Fatal("Operation: <", operation, "> does not exist")
	}

	if cuttingFactor != 0 {
		operation.NbrOutput = operation.NbrOutput*cuttingFactor
	}

	return operation
}

