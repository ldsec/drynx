package services

import (
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/unlynx/lib"
	"math"
	"time"
)

// API represents a client with the server to which he is connected and its public/private key pair.
type API struct {
	*onet.Client
	clientID   string
	entryPoint *network.ServerIdentity
	public     kyber.Point
	private    kyber.Scalar
}

//init of the network messages
func init() {
	network.RegisterMessage(libdrynx.GetLatestBlock{})
	network.RegisterMessage(libdrynx.RangeProofListBytes{})
	network.RegisterMessage(libdrynx.PublishedShufflingProofBytes{})
	network.RegisterMessage(libdrynx.PublishedKSListProofBytes{})
	network.RegisterMessage(libdrynx.PublishAggregationProofBytes{})
	network.RegisterMessage(libdrynx.PublishedListObfuscationProofBytes{})
}

// NewDrynxClient constructor of a client.
func NewDrynxClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	newClient := &API{
		Client:     onet.NewClient(libunlynx.SuiTe, ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Private,
	}

	//limit := int64(10000)
	limit := int64(100000)
	libdrynx.CreateDecryptionTable(limit, newClient.public, newClient.private)
	return newClient
}


// how to repartition the DPs: each server as a list of data providers
func RepartitionDPs(elServers *onet.Roster, elDPs *onet.Roster, dpRepartition []int64) map[string]*[]network.ServerIdentity {
	if len(dpRepartition) > len(elServers.List) {
		log.Fatal("Cannot assign the DPs to", len(dpRepartition), "servers (", len(elServers.List), ")")
	}

	dpToServers := make(map[string]*[]network.ServerIdentity, 0)
	count := 0
	for i, v := range elServers.List {
		index := v.String()
		if dpRepartition[i] == 0 {
			continue
		}
		value := make([]network.ServerIdentity, dpRepartition[i])
		dpToServers[index] = &value
		for j := range *dpToServers[index] {
			val := elDPs.List[count]
			count += 1
			(*dpToServers[index])[j] = *val
		}
	}
	return dpToServers
}

// Evaluate the performance of (trained) logistic regression model
func PerformanceEvaluation(weights []float64, XTest [][]float64, yTest []int64, means []float64,
	standardDeviations []float64) (float64,
	float64, float64, float64, float64) {
	fmt.Println("weights:", weights)

	if means != nil && standardDeviations != nil &&
		len(means) > 0 && len(standardDeviations) > 0 {
		// using global means and standard deviations, if given
		log.Lvl1("Standardising the testing set with global means and standard deviations...")
		XTest = encoding.StandardiseWith(XTest, means, standardDeviations)
	} else {
		// using local means and standard deviations, if not given
		log.Lvl1("Standardising the testing set with local means and standard deviations...")
		XTest = encoding.Standardise(XTest)
	}

	predictions := make([]int64, len(XTest))
	predictionsFloat := make([]float64, len(XTest))
	for i := range XTest {
		predictionsFloat[i] = encoding.PredictInClear(XTest[i], weights)
		predictions[i] = int64(math.Round(predictionsFloat[i]))
	}

	accuracy := encoding.Accuracy(predictions, yTest)
	precision := encoding.Precision(predictions, yTest)
	recall := encoding.Recall(predictions, yTest)
	fscore := encoding.Fscore(predictions, yTest)
	auc := encoding.AreaUnderCurve(predictionsFloat, yTest)

	fmt.Println("accuracy: ", accuracy)
	fmt.Println("precision:", precision)
	fmt.Println("recall:   ", recall)
	fmt.Println("F-score:  ", fscore)
	fmt.Println("AUC:      ", auc)
	return accuracy, precision, recall, fscore, auc
}

// Send Query
//______________________________________________________________________________________________________________________

// GenerateSurveyQuery generates a query with all the information in parameters
func (c *API) GenerateSurveyQuery(rosterServers, rosterVNs *onet.Roster, dpToServer map[string]*[]network.ServerIdentity,
	idToPublic map[string]kyber.Point, surveyID string, operation libdrynx.Operation, ranges []*[]int64,
	ps []*[]libdrynx.PublishSignatureBytes, proofs int64, obfuscation bool, thresholds []float64,
	diffP libdrynx.QueryDiffP, dpDataGen libdrynx.QueryDPDataGen, cuttingFactor int64, dpsUsed []*network.ServerIdentity) libdrynx.SurveyQuery {
	size1 := int64(0)
	size2 := int64(0)
	if ps != nil {
		size1 = int64(len(ps))
		size2 = int64(len(*ps[0]))
	}

	iVSigs := libdrynx.QueryIVSigs{InputValidationSigs: ps, InputValidationSize1: size1, InputValidationSize2: size2}

	test := make([][]int64, 0)
	test = append(test, []int64{int64(1)})

	//create the query
	sq := libdrynx.SurveyQuery{
		SurveyID:                   surveyID,
		RosterServers:              *rosterServers,
		ClientPubKey:               c.public,
		IntraMessage:               false,
		ServerToDP:                 dpToServer,
		DPsUsed:                    dpsUsed,
		IDtoPublic:                 idToPublic,
		Threshold:                  thresholds[0],
		RangeProofThreshold:        thresholds[1],
		ObfuscationProofThreshold:  thresholds[2],
		KeySwitchingProofThreshold: thresholds[3],

		// query statement
		Query: libdrynx.Query{
			Operation:   operation,
			Ranges:      ranges,
			DiffP:       diffP,
			Proofs:      proofs,
			Obfuscation: obfuscation,
			// data generation at DPs
			DPDataGen: dpDataGen,

			// identity blockchain infos
			IVSigs:        iVSigs,
			RosterVNs:     rosterVNs,
			CuttingFactor: cuttingFactor,
		},
	}

	return sq
}

// SendSurveyQuery creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyQuery(sq libdrynx.SurveyQuery) (*[]string, *[][]float64, error) {
	log.Lvl2("[API] <Drynx> Client", c.clientID, "is creating a query with SurveyID: ", sq.SurveyID)

	//send the query and get the answer
	sr := libdrynx.ResponseDP{}
	err := c.SendProtobuf(c.entryPoint, &sq, &sr)
	if err != nil {
		return nil, nil, err
	}

	log.Lvl2("[API] <Drynx> Client", c.clientID, "successfully executed the query with SurveyID ", sq.SurveyID)

	// decrypt/decode the result
	start := time.Now()

	log.Lvl2("[API] <Drynx> Client", c.clientID, "is decrypting the results")

	grp := make([]string, len(sr.Data))
	aggr := make([][]float64, len(sr.Data))
	count := 0

	for i, res := range sr.Data {
		grp[count] = i
		aggr[count] = encoding.Decode(res, c.private, sq.Query.Operation)
		count++
	}

	elapsed := time.Since(start)
	log.LLvl1("Decoding took", elapsed)

	log.Lvl2("[API] <Drynx> Client", c.clientID, "finished decrypting the results")
	return &grp, &aggr, nil
}
