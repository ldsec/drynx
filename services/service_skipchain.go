package services

import (
	"os"
	"sync"

	"time"

	"github.com/coreos/bbolt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/protocols"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/satori/go.uuid.v1"
)

var VerifyBitmap = skipchain.VerifierID(uuid.NewV5(uuid.NamespaceURL, "Bitmap"))
var VerificationBitmap = []skipchain.VerifierID{VerifyBitmap, skipchain.VerifyBase}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyQueryToVN handles the reception of the query at a VN
func (s *ServiceDrynx) HandleSurveyQueryToVN(recq *libdrynx.SurveyQueryToVN) (network.Message, error) {

	recq.SQ.Query.IVSigs.InputValidationSigs = recreateRangeSignatures(recq.SQ.Query.IVSigs)

	s.Mutex.Lock()
	var totalNbrProofs int
	log.Lvl2("[SERVICE] <VN> Server", s.ServerIdentity().String(), "received a Survey Query")

	s.Survey.Put(recq.SQ.SurveyID, Survey{
		SurveyQuery: recq.SQ,
		Mutex:       &sync.Mutex{},
	})

	// create the objects if it is the first time
	if s.Request == nil {
		s.Request = concurrent.NewConcurrentMap()
	}

	sizeQuery := make([]int, 0)
	proofsVerified := make(map[string]int64)
	//Put in the concurrent map the info that were calculated.
	size := libdrynx.QueryToProofsNbrs(recq.SQ)

	//Order of proof is Range, Shuffle, Aggr, obfuscation, KeySwitch
	sizeQuery = append(sizeQuery, size[0])
	sizeQuery = append(sizeQuery, size[2])
	sizeQuery = append(sizeQuery, size[3])
	sizeQuery = append(sizeQuery, size[1])
	sizeQuery = append(sizeQuery, size[4])
	totalNbrProofs = size[0] + size[2] + size[3] + size[1] + size[4]

	if s.ServerIdentity().String() == recq.SQ.Query.RosterVNs.List[0].String() {
		s.Request.Put(recq.SQ.SurveyID, &libdrynx.QueryInfo{Bitmap: proofsVerified, TotalNbrProofs: sizeQuery, Query: &recq.SQ, SharedBMChannel: make(chan map[string]int64, 100), SharedBMChannelToTerminate: make(chan struct{}, 100), EndVerificationChannel: make(chan skipchain.SkipBlock, 100)})
	} else {
		s.Request.Put(recq.SQ.SurveyID, &libdrynx.QueryInfo{Bitmap: proofsVerified, TotalNbrProofs: sizeQuery, Query: &recq.SQ})
	}

	if s.DBPath == "" {
		s.DBPath = "db:" + s.ServerIdentity().ID.String()
	}
	if s.DB == nil {
		db, err := OpenDB(s.DBPath)
		if err != nil {
			log.ErrFatal(err, "Could not open db")
		}
		s.DB = db
	}

	if s.Skipchain == nil {
		s.Skipchain = skipchain.NewClient()
	}

	s.Mutex.Unlock()

	if s.ServerIdentity().String() == recq.SQ.Query.RosterVNs.List[0].String() {
		go func() {
			// read all bitmaps
			aggregateBitmap := make(map[string]int64)
			for i := 0; i < len(recq.SQ.Query.RosterVNs.List); i++ {
				res := <-protocols.CastToQueryInfo(s.Request.Get(recq.SQ.SurveyID)).SharedBMChannel

				for key, value := range res {
					aggregateBitmap[key] = value
				}
			}

			// terminate all protocols
			for i := 0; i < totalNbrProofs; i++ {
				protocols.CastToQueryInfo(s.Request.Get(recq.SQ.SurveyID)).SharedBMChannelToTerminate <- struct{}{}
			}

			startBI := libunlynx.StartTimer("BI")

			//Create the data structure that will be inserted in the block
			dataBlock := new(libdrynx.DataBlock)
			dataBlock.Sample = 0.4
			dataBlock.SurveyID = recq.SQ.SurveyID
			dataBlock.Time = time.Now()
			dataBlock.Proofs = aggregateBitmap
			dataBlock.ServerNumber = int64(len(recq.SQ.Query.RosterVNs.List))
			dataBlock.Roster = recq.SQ.Query.RosterVNs

			dataBytes, err := network.Marshal(dataBlock)
			if err != nil {
				log.Fatal("Error in marshaling proofs data to insert ,", err)
			}

			// no skipchain yet created
			var newSB *skipchain.SkipBlock

			s.Mutex.Lock()
			if s.LastSkipBlock == nil {
				newSB, err = CreateProofSkipchain(s.Skipchain, recq.SQ.Query.RosterVNs, dataBytes)
				if err != nil || newSB == nil {
					log.Fatal("Error creating the genesis block:", err)
				}

				//Store Genesis in DB
				genesisBytes, _ := network.Marshal(newSB)

				log.LLvl1("SIZE OF BLOCK:", len(genesisBytes))
				libdrynx.UpdateDB(s.DB, "genesis", "genesis", genesisBytes)

				s.LastSkipBlock = newSB

			} else {
				newSB, err = AppendProofSkipchain(s.Skipchain, recq.SQ.Query.RosterVNs, dataBytes, s.LastSkipBlock, recq.SQ.SurveyID)
				if err != nil || newSB == nil {
					log.Fatal("Error appending the block to the chain:", err)
				}

				//Store new block in DB
				libdrynx.UpdateDB(s.DB, "mapping", recq.SQ.SurveyID, []byte(newSB.Hash))

				s.LastSkipBlock = newSB
			}
			s.Mutex.Unlock()

			libunlynx.EndTimer(startBI)

			protocols.CastToQueryInfo(s.Request.Get(recq.SQ.SurveyID)).EndVerificationChannel <- *newSB
		}()
	}

	return nil, nil
}

// HandleEndVerification handles the reception of an end verification request
func (s *ServiceDrynx) HandleEndVerification(msg *libdrynx.EndVerificationRequest) (network.Message, error) {
	//block until all verification of the proofs is done (and of course inserted in the skipchain)
	sb := <-protocols.CastToQueryInfo(s.Request.Get(msg.QueryInfoID)).EndVerificationChannel
	return &libdrynx.Reply{Latest: &sb}, nil
}

// HandleGetGenesis handles the reception of a genesis block request
func (s *ServiceDrynx) HandleGetGenesis(request *libdrynx.GetGenesis) (network.Message, error) {

	genesisBytes := make([]byte, 0)
	err := s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("genesis"))
		genesisBytes = b.Get([]byte("genesis"))
		return nil
	})

	if err != nil {
		return nil, err
	}
	_, block, err := network.Unmarshal(genesisBytes, libunlynx.SuiTe)

	if err != nil {
		return nil, err
	}
	return &libdrynx.Reply{Latest: block.(*skipchain.SkipBlock)}, nil

}

// HandleGetLatestBlock handles the last block request reception
func (s *ServiceDrynx) HandleGetLatestBlock(request *libdrynx.GetLatestBlock) (network.Message, error) {
	timeGet := libunlynx.StartTimer("GetBlock")
	chain, err := s.Skipchain.GetUpdateChain(request.Roster, request.Sb.Hash)
	libunlynx.EndTimer(timeGet)
	if err != nil {
		return nil, err
	}

	return &libdrynx.Reply{Latest: chain.Update[len(chain.Update)-1]}, nil
}

// HandleGetBlock handles the request for a block
func (s *ServiceDrynx) HandleGetBlock(request *libdrynx.GetBlock) (network.Message, error) {
	blockID := skipchain.SkipBlockID{}

	if s.DB == nil {
		db, _ := OpenDB(s.DBPath)
		s.DB = db
	}

	err := s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("genesis"))
		blockIDbytes := b.Get([]byte(request.ID))
		if len(blockIDbytes) == 0 {
			b = tx.Bucket([]byte("mapping"))
			blockIDbytes = b.Get([]byte(request.ID))
		}
		blockID = skipchain.SkipBlockID(blockIDbytes)
		return nil
	})
	if err != nil {
		log.Error("Error getting index" + err.Error())
	}

	block, err := s.Skipchain.GetSingleBlock(request.Roster, blockID)

	if err != nil {
		return nil, err
	}

	return &libdrynx.Reply{Latest: block}, nil
}

//HandleGetProofs handle the request to send back proof for a given query ID
//It is sent as a key,value (string,[]byte)
func (s *ServiceDrynx) HandleGetProofs(request *libdrynx.GetProofs) (network.Message, error) {
	//Open the DB if it is not open
	timeGetProof := libunlynx.StartTimer(s.ServerIdentity().String() + "_GetProofs")
	if s.DB == nil {
		db, err := OpenDB(s.DBPath)
		if err != nil {
			log.ErrFatal(err, "Could not open db")
		}
		s.DB = db
	}
	//Iterate over each bucket
	result := make(map[string][]byte)

	if err := s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(request.ID + "/range"))
		if b == nil {
			log.Info("No bucket - range")
		} else {
			c := b.Cursor()
			//For each key in this bucket (each proofs)
			for k, v := c.First(); k != nil; k, v = c.Next() {
				result[string(k)] = v
			}
		}

		//Bucket aggregation
		b = tx.Bucket([]byte(request.ID + "/aggregation"))
		if b == nil {
			log.Info("No bucket - aggregation")
		} else {
			c := b.Cursor()
			//For each key in this bucket (each proofs)
			for k, v := c.First(); k != nil; k, v = c.Next() {
				result[string(k)] = v
			}
		}

		//Bucket obfuscation
		b = tx.Bucket([]byte(request.ID + "/obfuscation"))
		if b == nil {
			log.Info("No bucket - obfuscation")
		} else {
			c := b.Cursor()
			//For each key in this bucket (each proofs)
			for k, v := c.First(); k != nil; k, v = c.Next() {
				result[string(k)] = v
			}
		}

		//Bucket shuffle
		b = tx.Bucket([]byte(request.ID + "/shuffle"))
		if b == nil {
			log.Info("No bucket - shuffle")
		} else {
			c := b.Cursor()
			//For each key in this bucket (each proofs)
			for k, v := c.First(); k != nil; k, v = c.Next() {
				result[string(k)] = v
			}
		}

		//Bucket keyswitch
		b = tx.Bucket([]byte(request.ID + "/keyswitch"))
		if b == nil {
			log.Info("No bucket - keyswitch")
		} else {
			c := b.Cursor()
			//For each key in this bucket (each proofs)
			for k, v := c.First(); k != nil; k, v = c.Next() {
				result[string(k)] = v
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	libunlynx.EndTimer(timeGetProof)
	return &libdrynx.ProofsAsMap{Proofs: result}, nil
}

// HandleCloseDB handles the request to close database
func (s *ServiceDrynx) HandleCloseDB(request *libdrynx.CloseDB) (network.Message, error) {
	if s.DB != nil {
		log.Lvl2("Closing DB")

		err := s.DB.Close()
		if err != nil {
			log.Error("Close database failed with: " + err.Error())
		}

		s.DB = nil
		if request.Close != 0 {
			log.Lvl2("Removing DB file")
			err := os.Remove(s.DBPath)
			if err != nil {
				return nil, err
			}
		}
	}
	return nil, nil
}

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProofCollectionProtocolInstance creates a proof collection protocol
func (s *ServiceDrynx) NewProofCollectionProtocolInstance(tn *onet.TreeNodeInstance, target string) (onet.ProtocolInstance, error) {
	pi, err := protocols.NewProofCollectionProtocol(tn)
	if err != nil {
		return nil, err
	}

	proofCollection := pi.(*protocols.ProofCollectionProtocol)
	if !tn.IsRoot() {
		survey := castToSurvey(s.Survey.Get(target))

		// TODO: Add channel to ensure that the query has been set
		proofCollection.SQ = survey.SurveyQuery
		proofCollection.Mutex = survey.Mutex
		proofCollection.Skipchain = s.Skipchain
		proofCollection.Request = s.Request
		proofCollection.DB = s.DB

		// if root of the VN
		if s.ServerIdentity().String() == survey.SurveyQuery.Query.RosterVNs.List[0].String() {
			proofCollection.SharedBMChannel = protocols.CastToQueryInfo(s.Request.Get(target)).SharedBMChannel
			proofCollection.SharedBMChannelToTerminate = protocols.CastToQueryInfo(s.Request.Get(target)).SharedBMChannelToTerminate
		}
	}

	return pi, nil
}

// CreateProofCollectionPIs create a set of ProofCollection protocol instances to be used in the protocols: Aggregation, Shuffle, ...
func (s *ServiceDrynx) CreateProofCollectionPIs(tree *onet.Tree, targetSurvey, name string) onet.ProtocolInstance {
	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, protocols.ProofCollectionProtocolName)

	conf := onet.GenericConfig{Data: []byte(targetSurvey)}
	pi, err := s.NewProtocol(tn, &conf)
	if err != nil {
		log.Fatal("Error running" + name)
	}

	s.RegisterProtocolInstance(pi)
	return pi
}

// Verifier Functions
//______________________________________________________________________________________________________________________

//verifyFuncBitmap is used in the Lemal framework to verify if a block's data is correct or not.
func (s *ServiceDrynx) verifyFuncBitmap(newID []byte, newSB *skipchain.SkipBlock) bool {

	//Get data of the newBlock
	_, msg, err := network.Unmarshal(newSB.Data, libunlynx.SuiTe)
	if err != nil {
		log.Fatal("Error in Verify Bitmap")
		return false
	}

	//Get bitmap that was inserted in newBlock
	blockData := msg.(*libdrynx.DataBlock)
	bitMap := blockData.Proofs
	bitMapFromServ := make(map[string]int64)

	//Read operation on the bitmap stored on DB of the server
	err = s.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(s.ServerIdentity().Address))
		if b == nil {
			log.Fatal("No bucket")
		}
		v := b.Get([]byte(blockData.SurveyID + "/map"))
		_, message, _ := network.Unmarshal(v, libunlynx.SuiTe)
		result := message.(*libdrynx.BitMap)
		bitMapFromServ = result.BitMap
		return nil
	})

	//Compare the bitmap you get from DB to all bitmap Stored in Block
	for i, v := range bitMapFromServ {
		if bitMap[i] != v {
			log.Lvl2(i, v)
			log.Lvl2("Some trouble in the block")
			return false
		}
	}

	return true

}

// Support Functions
//______________________________________________________________________________________________________________________

func generateProofCollectionRoster(root *network.ServerIdentity, rosterVNs *onet.Roster) *onet.Roster {
	roster := make([]*network.ServerIdentity, 0)
	roster = append(roster, root)

	for _, vn := range rosterVNs.List {
		roster = append(roster, vn)
	}
	return onet.NewRoster(roster)
}

func (s *ServiceDrynx) generateMapPIs(query *libdrynx.SurveyQuery) map[string]onet.ProtocolInstance {
	mapPIs := make(map[string]onet.ProtocolInstance)

	tree := generateProofCollectionRoster(s.ServerIdentity(), query.Query.RosterVNs).GenerateStar()

	piAggregation := s.CreateProofCollectionPIs(tree, query.SurveyID, protocols.ProofCollectionProtocolName)
	mapPIs["aggregation/"+s.ServerIdentity().String()] = piAggregation

	if query.Query.Obfuscation {
		piObfuscation := s.CreateProofCollectionPIs(tree, query.SurveyID, protocols.ProofCollectionProtocolName)
		mapPIs["obfuscation/"+s.ServerIdentity().String()] = piObfuscation
	}

	// there is differential privacy
	if query.Query.DiffP.NoiseListSize > 0 {
		piShuffle := s.CreateProofCollectionPIs(tree, query.SurveyID, protocols.ProofCollectionProtocolName)
		mapPIs["shuffle/"+s.ServerIdentity().String()] = piShuffle
	}

	piKeySwitch := s.CreateProofCollectionPIs(tree, query.SurveyID, protocols.ProofCollectionProtocolName)
	mapPIs["keyswitch/"+s.ServerIdentity().String()] = piKeySwitch

	return mapPIs
}

//OpenDB opens/creates a database
func OpenDB(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// CreateProofSkipchain creates the skipchain
func CreateProofSkipchain(sk *skipchain.Client, roster *onet.Roster, dataBytes []byte) (*skipchain.SkipBlock, error) {
	timeGenesis := libunlynx.StartTimer("Genesis")
	root, err := sk.CreateGenesis(roster, 1, 1, VerificationBitmap, dataBytes, nil)
	if err != nil {
		return nil, err
	}
	libunlynx.EndTimer(timeGenesis)
	return root, nil
}

// AppendProofSkipchain appends a new block to the chain
func AppendProofSkipchain(sk *skipchain.Client, roster *onet.Roster, dataBytes []byte, sb *skipchain.SkipBlock, surveyID string) (*skipchain.SkipBlock, error) {
	timeAppendBlock := libunlynx.StartTimer("AppendBlock")
	//Get the chain
	chain, err := sk.GetUpdateChain(roster, sb.Hash)
	if err != nil {
		return nil, err
	}

	//Update chain
	latest := chain.Update[len(chain.Update)-1]
	newSB, err := sk.StoreSkipBlock(latest, roster, dataBytes)
	if err != nil {
		return nil, err
	}
	libunlynx.EndTimer(timeAppendBlock)
	return newSB.Latest, nil
}
