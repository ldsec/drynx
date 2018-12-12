package protocols

import (
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/coreos/bbolt"
	"github.com/dedis/cothority/skipchain"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/drynx/lib"
	"sync"
)

// ProofCollectionProtocolName is the registered name for the proofs collection by the skipchain protocol.
const ProofCollectionProtocolName = "ProofCollection"

func init() {
	network.RegisterMessage(AnnouncementPCMessage{})
	network.RegisterMessage(ProofCollectionMessage{})
	network.RegisterMessage(BitmapCollectionMessage{})
	network.RegisterMessage(libdrynx.BitMap{})
	onet.GlobalProtocolRegister(ProofCollectionProtocolName, NewProofCollectionProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// AnnouncementPCMessage message sent (with the query) to trigger a proof collection protocol.
type AnnouncementPCMessage struct {
	Proof libdrynx.ProofRequest
}

// ProofCollectionMessage message is used to signal root node that the proof was processed by all verifying nodes
type ProofCollectionMessage struct {
	Result int64
	SB     *skipchain.SkipBlock
}

// BitmapCollectionMessage message used to collect the bitmap information
type BitmapCollectionMessage struct {
	Bitmap map[string]int64
	ID     string
	New    bool
	Roster *onet.Roster
	sbHash skipchain.SkipBlockID
}

// ReplyPCMessage bitmap message
type ReplyPCMessage struct {
	Bitmap map[string]int64
	SB     *skipchain.SkipBlock
}

// Structs
//______________________________________________________________________________________________________________________

// AnnouncementPCStruct struct to send AnnouncementPCMessage message
type AnnouncementPCStruct struct {
	*onet.TreeNode
	AnnouncementPCMessage
}

// ProofCollectionStruct is the wrapper of DataCollectionMessage to be used in a channel
type ProofCollectionStruct struct {
	*onet.TreeNode
	ProofCollectionMessage
}

// BitmapCollectionStruct is the wrapper of BitmapCollectionStruct to be used in a channel
type BitmapCollectionStruct struct {
	*onet.TreeNode
	BitmapCollectionMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// ProofCollectionProtocol hold the state of a proofs collection protocol instance.
type ProofCollectionProtocol struct {
	*onet.TreeNodeInstance

	// ----- Service -----
	Skipchain *skipchain.Client
	//Contains size for a query, as well as the bitmap for this query
	Request *concurrent.ConcurrentMap
	//the name of DB and the DB in itself is dedicated to the server.
	DBPath string
	DB     *bbolt.DB
	//To make everything thread safe (database access and updating parameters)
	Mutex *sync.Mutex
	// -------------------

	// Protocol feedback channel
	FeedbackChannel chan ReplyPCMessage

	// Protocol communication channels
	AnnouncementChannel     chan AnnouncementPCStruct
	ProofCollectionChannel  chan ProofCollectionStruct
	BitmapCollectionChannel chan BitmapCollectionStruct

	// Service shared channel (a channel that belongs to the parent service)
	SharedBMChannel            chan map[string]int64
	SharedBMChannelToTerminate chan struct{}

	// proof statement
	Proof libdrynx.ProofRequest // the proof must be sent to each node before the protocol can start

	// query statement
	SQ libdrynx.SurveyQuery
}

// CastToQueryInfo get in the concurrent map the queryInfo
func CastToQueryInfo(object interface{}, err error) *libdrynx.QueryInfo {
	if err != nil {
		log.Fatal("Error reading map")
	}
	if object == nil {
		return nil
	}
	return object.(*libdrynx.QueryInfo)
}

// NewProofCollectionProtocol constructs a ProofCollection protocol instance.
func NewProofCollectionProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pcp := &ProofCollectionProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan ReplyPCMessage),
	}

	err := pcp.RegisterChannel(&pcp.AnnouncementChannel)
	if err != nil {
		return nil, errors.New("couldn't register announcement channel: " + err.Error())
	}

	err = pcp.RegisterChannel(&pcp.ProofCollectionChannel)
	if err != nil {
		return nil, errors.New("couldn't register proof collection channel: " + err.Error())
	}

	err = pcp.RegisterChannel(&pcp.BitmapCollectionChannel)
	if err != nil {
		return nil, errors.New("couldn't register bitmap collection channel: " + err.Error())
	}

	return pcp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ProofCollectionProtocol) Start() error {

	if p.Proof.RangeProof != nil {
		log.Lvl2("["+p.Name()+"]", "starts a Proof Collection Protocol: RANGE")
	} else if p.Proof.AggregationProof != nil {
		log.Lvl2("["+p.Name()+"]", "starts a Proof Collection Protocol: AGGREGATION")
	} else if p.Proof.ObfuscationProof != nil {
		log.Lvl2("["+p.Name()+"]", "starts a Proof Collection Protocol: OBFUSCATION")
	} else if p.Proof.ShuffleProof != nil {
		log.Lvl2("["+p.Name()+"]", "starts a Proof Collection Protocol: SHUFFLE")
	} else if p.Proof.KeySwitchProof != nil {
		log.Lvl2("["+p.Name()+"]", "starts a Proof Collection Protocol: KEY SWITCH")
	} else {
		log.Fatal("Did not recognise the type of proof")
	}

	for _, node := range p.Tree().List() {
		// the root node sends an announcement message to all the nodes
		if !node.IsRoot() {
			if err := p.SendTo(node, &AnnouncementPCMessage{Proof: p.Proof}); err != nil {
				log.Fatal(err)
			}
		}
	}

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ProofCollectionProtocol) Dispatch() error {
	defer p.Done()

	// 1. If not root -> wait for announcement message from root
	if !p.IsRoot() {
		ac := <-p.AnnouncementChannel
		log.Lvl2("["+p.Name()+"]", "received an announcement message for a Proof Collection Protocol.")

		p.Proof = ac.Proof

		var verif int64
		var err error
		var sb *skipchain.SkipBlock

		//verifyProofstart := time.Now()

		// verify which type of proof it is
		if p.Proof.RangeProof != nil {

			verif, err = p.Proof.RangeProof.VerifyProof(*p.ServerIdentity(), p.SQ)

			// store range proof list in db and skipchain (transaction)
			sb, err = p.storeProof(
				0,
				"range",
				p.Proof.RangeProof.SurveyID,
				p.Proof.RangeProof.SenderID,
				p.Proof.RangeProof.DifferInfo,
				verif,
				p.Proof.RangeProof.Data,
				p.Proof.RangeProof.Signature,
				p.Proof.RangeProof.Roster,
				p.Proof.RangeProof.SB)

		} else if p.Proof.AggregationProof != nil {
			verif, err = p.Proof.AggregationProof.VerifyProof(*p.ServerIdentity(), p.SQ)
			// store aggregation proof in db and skipchain (transaction)
			sb, err = p.storeProof(
				1,
				"aggregation",
				p.Proof.AggregationProof.SurveyID,
				p.Proof.AggregationProof.SenderID,
				p.Proof.AggregationProof.DifferInfo,
				verif,
				p.Proof.AggregationProof.Data,
				p.Proof.AggregationProof.Signature,
				p.Proof.AggregationProof.Roster,
				p.Proof.AggregationProof.SB)

		} else if p.Proof.ObfuscationProof != nil {
			verif, err = p.Proof.ObfuscationProof.VerifyProof(*p.ServerIdentity(), p.SQ)
			// store aggregation proof in db and skipchain (transaction)
			sb, err = p.storeProof(
				2,
				"obfuscation",
				p.Proof.ObfuscationProof.SurveyID,
				p.Proof.ObfuscationProof.SenderID,
				p.Proof.ObfuscationProof.DifferInfo,
				verif,
				p.Proof.ObfuscationProof.Data,
				p.Proof.ObfuscationProof.Signature,
				p.Proof.ObfuscationProof.Roster,
				p.Proof.ObfuscationProof.SB)

		} else if p.Proof.ShuffleProof != nil {
			verif, err = p.Proof.ShuffleProof.VerifyProof(*p.ServerIdentity(), p.SQ)
			// store shuffle proof in db and skipchain (transaction)
			sb, err = p.storeProof(
				3,
				"shuffle",
				p.Proof.ShuffleProof.SurveyID,
				p.Proof.ShuffleProof.SenderID,
				p.Proof.ShuffleProof.DifferInfo,
				verif,
				p.Proof.ShuffleProof.Data,
				p.Proof.ShuffleProof.Signature,
				p.Proof.ShuffleProof.Roster,
				p.Proof.ShuffleProof.SB)

		} else if p.Proof.KeySwitchProof != nil {
			verif, err = p.Proof.KeySwitchProof.VerifyProof(*p.ServerIdentity(), p.SQ)

			// store key switch proof in db and skipchain (transaction)
			sb, err = p.storeProof(
				4,
				"keyswitch",
				p.Proof.KeySwitchProof.SurveyID,
				p.Proof.KeySwitchProof.SenderID,
				p.Proof.KeySwitchProof.DifferInfo,
				verif,
				p.Proof.KeySwitchProof.Data,
				p.Proof.KeySwitchProof.Signature,
				p.Proof.KeySwitchProof.Roster,
				p.Proof.KeySwitchProof.SB)

		} else {log.Fatal("Did not recognise the type of proof")}

		//elapsedVerifyProof := time.Since(verifyProofstart)
		//log.LLvl1("Proof verification took ", elapsedVerifyProof)

		if err != nil {log.Fatal("Error when verifying the proof:", err)}

		dcm := ProofCollectionMessage{Result: verif, SB: sb}
		// 2. Send message to root
		p.SendTo(p.Root(), &dcm)
	} else {
		// 3. If root wait for all the verifying nodes to process the proofs
		bitmap := make(map[string]int64)
		finalRes := ReplyPCMessage{Bitmap: bitmap}

		for i := 0; i < len(p.Tree().List())-1; i++ {
			res := <-p.ProofCollectionChannel

			finalRes.Bitmap[res.ServerIdentity.String()] = res.Result

			if res.SB != nil {
				finalRes.SB = res.SB
			}
		}
		p.FeedbackChannel <- finalRes
	}

	return nil
}

func (p *ProofCollectionProtocol) storeProof(index int, typeProof, surveyID, senderID, potentialDeterministicInfo string, verificationResult int64, data, signature []byte, roster *onet.Roster, sb *skipchain.SkipBlock) (*skipchain.SkipBlock, error) {
	p.Mutex.Lock()

	remainingProofs := CastToQueryInfo(p.Request.Get(surveyID)).TotalNbrProofs[index]
	rootVN := roster.List[0].Equal(p.ServerIdentity())

	if remainingProofs > 0 {
		//timeHandleProof := libunlynx.StartTimer(p.ServerIdentity().String() + "_Handle" + strings.Title(typeProof))

		//Put in the bitmap the value of the verification
		//Key is SurveyID + type_of_proof + senderID + addiInfo + serverID
		nameOfProof := surveyID + "/" + typeProof + "/" + senderID + "/" + potentialDeterministicInfo + "/" + p.ServerIdentity().Address.String()
		qi := CastToQueryInfo(p.Request.Get(string(surveyID)))
		qi.Bitmap[nameOfProof] = verificationResult
		p.Request.Replace(surveyID, qi)

		//Put in the DB the proof received. Bucket is queryID + type
		//Key is SurveyID + type_of_proof + senderID + addiInfo + serverID
		//TODO: append signature to data

		if typeProof != "shuffle" {
			libdrynx.UpdateDB(p.DB, surveyID+"/"+typeProof, nameOfProof, data)
		}

		//Decrease size of proof expected for this type by 1
		qi.TotalNbrProofs[index]--
		p.Request.Replace(surveyID, qi)

		//libunlynx.EndTimer(timeHandleProof)

		//--------------------------------------------------------------------------------------------------------------

		//Check if all proofs has been processed.
		proofsRemaining := int64(0)
		for _, count := range CastToQueryInfo(p.Request.Get(surveyID)).TotalNbrProofs {
			proofsRemaining += count
		}
		log.Lvl2("VN", p.ServerIdentity().String(), "is checking the number of proofs.", proofsRemaining, "proofs remaining.")
		p.Mutex.Unlock()

		if proofsRemaining == 0 {
			log.Lvl2("VN", p.ServerIdentity().String(), "received all expected proofs.")

			mapByte, err := network.Marshal(&libdrynx.BitMap{BitMap: CastToQueryInfo(p.Request.Get(string(surveyID))).Bitmap})
			if err != nil {
				log.Fatal("Cannot marshalize map", err)
			}

			libdrynx.UpdateDB(p.DB, p.ServerIdentity().Address.String(), surveyID+"/map", mapByte)

			//If not root, send bitmap
			if !rootVN {
				// send to root of the VNs
				for _, treeNode := range p.Tree().List() {
					if treeNode.ServerIdentity.String() == roster.List[0].String() {
						bm := CastToQueryInfo(p.Request.Get(string(surveyID))).Bitmap
						err := p.SendTo(treeNode, &BitmapCollectionMessage{Bitmap: bm})
						if err != nil {
							log.Fatal(err)
						}
					}
				}
				// If root
			} else {
				p.SharedBMChannel <- CastToQueryInfo(p.Request.Get(string(surveyID))).Bitmap
			}
		}

		//if root of VNs wait for bitmaps
		if rootVN {
			go func() {
				<-p.SharedBMChannelToTerminate
				err := p.SendTo(p.TreeNode(), &BitmapCollectionMessage{})
				if err != nil {
					log.Fatal(err)
				}
			}()

			for i := 0; i < len(p.Tree().List())-1; i++ {
				bitmap := <-p.BitmapCollectionChannel

				// if the message was sent by the go routine
				if bitmap.ServerIdentity.String() == p.ServerIdentity().String() {
					return nil, nil // terminate
				}

				p.SharedBMChannel <- bitmap.Bitmap
			}
		}

	} else {
		p.Mutex.Unlock()
		return nil, errors.New("did not expect more " + typeProof + " proofs")
	}
	return nil, nil
}
