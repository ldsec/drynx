package services

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib"
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
	network.RegisterMessage(lib.GetLatestBlock{})
	network.RegisterMessage(lib.RangeProofListBytes{})
	network.RegisterMessage(lib.PublishedShufflingProofBytes{})
	network.RegisterMessage(lib.PublishedKSListProofBytes{})
	network.RegisterMessage(lib.PublishAggregationProofBytes{})
	network.RegisterMessage(lib.PublishedListObfuscationProofBytes{})

}

// NewLeMalClient constructor of a client.
func NewLeMalClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	newClient := &API{
		Client:     onet.NewClient(libunlynx.SuiTe, ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Private,
	}

	limit := 10000
	// we decrypt a big value to create the hashtable and have a constant decryption time
	dummy := libunlynx.EncryptInt(newClient.public, int64(limit))
	libunlynx.DecryptIntWithNeg(newClient.private, *dummy)
	return newClient
}

// Send Query
//______________________________________________________________________________________________________________________

func (c *API) GenerateSurveyQuery(rosterServers, rosterVNs *onet.Roster, dpToServer map[string]*[]network.ServerIdentity, idToPublic map[string]kyber.Point, surveyID string, operation lib.Operation, ranges []*[]int64, ps []*[]lib.PublishSignatureBytes, proofs int, obfuscation bool, thresholds []float64, diffP lib.QueryDiffP, dpDataGen lib.QueryDPDataGen, cuttingFactor int) lib.SurveyQuery {
	size1 := 0
	size2 := 0
	if ps != nil {
		size1 = len(ps)
		size2 = len(*ps[0])
	}

	iVSigs := lib.QueryIVSigs{InputValidationSigs: ps, InputValidationSize1: size1, InputValidationSize2: size2}

	test := make([][]int64, 0)
	test = append(test, []int64{int64(1)})

	//create the query
	sq := lib.SurveyQuery{
		SurveyID:                   surveyID,
		RosterServers:              *rosterServers,
		ClientPubKey:               c.public,
		IntraMessage:               false,
		ServerToDP:                 dpToServer,
		IDtoPublic:                 idToPublic,
		Threshold:                  thresholds[0],
		RangeProofThreshold:        thresholds[1],
		ObfuscationProofThreshold:  thresholds[2],
		KeySwitchingProofThreshold: thresholds[3],


		// query statement
		Query: lib.Query{
			Operation:   operation,
			Ranges:      ranges,
			DiffP:       diffP,
			Proofs:      proofs,
			Obfuscation: obfuscation,
			// data generation at DPs
			DPDataGen: dpDataGen,

			// identity blockchain infos
			IVSigs:    iVSigs,
			RosterVNs: rosterVNs,
			CuttingFactor: cuttingFactor,
		},
	}
	return sq
}

// SendSurveyQuery creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyQuery(sq lib.SurveyQuery) (*[]string, *[][]float64, error) {
	log.Lvl2("[API] <LEMAL> Client", c.clientID, "is creating a query with SurveyID: ", sq.SurveyID)

	//send the query and get the answer
	sr := lib.ResponseDP{}
	err := c.SendProtobuf(c.entryPoint, &sq, &sr)
	if err != nil {
		return nil, nil, err
	}

	log.Lvl2("[API] <LEMAL> Client", c.clientID, "successfully executed the query with SurveyID ", sq.SurveyID)

	// decrypt/decode the result
	clientDecode := libunlynx.StartTimer("Decode")
	log.Lvl2("[API] <LEMAL> Client", c.clientID, "is decrypting the results")

	grp := make([]string, len(sr.Data))
	aggr := make([][]float64, len(sr.Data))
	count := 0
	for i, res := range sr.Data {
		grp[count] = i
		aggr[count] = encoding.Decode(res, c.private, sq.Query.Operation)
		count++
	}
	libunlynx.EndTimer(clientDecode)

	log.Lvl2("[API] <LEMAL> Client", c.clientID, "finished decrypting the results")
	return &grp, &aggr, nil
}
