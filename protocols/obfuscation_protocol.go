// The collective aggregation protocol permits the cothority to collectively aggregate the local
// results of all the servers.
// It uses the tree structure of the cothority. The root sends down an aggregation trigger message. The leafs
// respond with their local result and other nodes aggregate what they receive before forwarding the
// aggregation result up the tree until the root can produce the final result.

package protocols

import (
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/drynx/lib"
)

// CollectiveAggregationProtocolName is the registered name for the collective aggregation protocol.
const ObfuscationProtocolName = "Obfuscation"

func init() {
	network.RegisterMessage(ObfuscationDownMessage{})
	network.RegisterMessage(ChildAggregatedDataMessage{})
	network.RegisterMessage(ObfuscationUpMessage{})
	network.RegisterMessage(ObfuscationLengthMessage{})
	onet.GlobalProtocolRegister(ObfuscationProtocolName, NewObfuscationProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// ObfuscationDownMessage message sent to trigger an aggregation protocol.
type ObfuscationDownMessage struct {
	Data libunlynx.CipherVector
}

// ChildAggregatedDataMessage contains one node's aggregated data.
type ObfuscationUpMessage struct {
	ChildData libunlynx.CipherVector
}

// ObfuscationUpBytesMessage is ChildAggregatedDataMessage in bytes.
type ObfuscationUpBytesMessage struct {
	Data []byte
}

// ObfuscationUpBytesMessage is ChildAggregatedDataMessage in bytes.
type ObfuscationDownBytesMessage struct {
	Data []byte
}

// CADBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type ObfuscationLengthMessage struct {
	Length int
}

// Structs
//______________________________________________________________________________________________________________________

type ObfuscationDownStruct struct {
	*onet.TreeNode
	ObfuscationDownMessage
}

type ObfuscationDownBytesStruct struct {
	*onet.TreeNode
	ObfuscationDownBytesMessage
}

type ObfuscationUpStruct struct {
	*onet.TreeNode
	ObfuscationUpMessage
}

type ObfuscationUpBytesStruct struct {
	*onet.TreeNode
	ObfuscationUpBytesMessage
}

type ObfuscationLengthStruct struct {
	*onet.TreeNode
	ObfuscationLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// CollectiveAggregationProtocol performs an aggregation of the data held by every node in the cothority.
type ObfuscationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan libunlynx.CipherVector

	// Protocol communication channels
	DataReferenceChannel chan ObfuscationDownBytesStruct
	LengthNodeChannel    chan []ObfuscationLengthStruct
	ChildDataChannel     chan []ObfuscationUpBytesStruct

	// Protocol state data
	ToObfuscateData libunlynx.CipherVector
	Proofs          int
	Query           *libdrynx.SurveyQuery

	// Protocol proof data
	MapPIs map[string]onet.ProtocolInstance
}

// NewCollectiveAggregationProtocol initializes the protocol instance.
func NewObfuscationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pop := &ObfuscationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libunlynx.CipherVector),
	}

	err := pop.RegisterChannel(&pop.DataReferenceChannel)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = pop.RegisterChannel(&pop.ChildDataChannel)
	if err != nil {
		log.Fatal(err)
		return nil, errors.New("couldn't register child-data channel: " + err.Error())
	}

	if err := pop.RegisterChannel(&pop.LengthNodeChannel); err != nil {
		log.Fatal(err)
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return pop, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *ObfuscationProtocol) Start() error {
	if p.ToObfuscateData == nil {
		return errors.New("no data reference provided for aggregation")
	}
	log.Lvl2("[OBFUSCATION PROTOCOL] <LEMAL> Server", p.ServerIdentity(), " started an Obfuscation Protocol (", len(p.ToObfuscateData), "ciphertext(s) )")
	bytesMessage, length := p.ToObfuscateData.ToBytes()

	p.SendToChildren(&ObfuscationLengthMessage{Length: length})
	p.SendToChildren(&ObfuscationDownBytesMessage{bytesMessage})
	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *ObfuscationProtocol) Dispatch() error {
	defer p.Done()

	// 1. Aggregation announcement phase
	if !p.IsRoot() {
		p.obfuscationAnnouncementPhase()
	}
	// 2. Ascending aggregation phase
	obfuscatededData := p.ascendingObfuscationPhase()
	log.Lvl2("[OBFUSCATION PROTOCOL] <LEMAL> Server", p.ServerIdentity(), " completed obfuscation phase (", len(obfuscatededData), "group(s) )")

	// 3. Response reporting
	if p.IsRoot() {
		p.FeedbackChannel <- obfuscatededData
	}
	return nil
}

// Announce forwarding down the tree.
func (p *ObfuscationProtocol) obfuscationAnnouncementPhase() {
	lengthMessage := <-p.LengthNodeChannel
	dataReferenceMessage := <-p.DataReferenceChannel

	cv := *libunlynx.NewCipherVector(lengthMessage[0].Length)
	cv.FromBytes(dataReferenceMessage.Data, lengthMessage[0].Length)
	p.ToObfuscateData = cv

	if !p.IsLeaf() {
		p.SendToChildren(&ObfuscationLengthMessage{Length: lengthMessage[0].Length})
		p.SendToChildren(&ObfuscationDownBytesMessage{Data: dataReferenceMessage.Data})
	}
}

type PrepareObfuscationProof struct {
	C, Co libunlynx.CipherText
	S     kyber.Scalar
}

// Results pushing up the tree containing aggregation results.
func (p *ObfuscationProtocol) ascendingObfuscationPhase() libunlynx.CipherVector {

	//roundTotComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(ascendingAggregation)")

	proofsCs := make([]libunlynx.CipherText, len(p.ToObfuscateData))
	proofsCos := make([]libunlynx.CipherText, len(p.ToObfuscateData))
	proofsSs := make([]kyber.Scalar, len(p.ToObfuscateData))

	wg := libunlynx.StartParallelize(len(p.ToObfuscateData))
	for i, v := range p.ToObfuscateData {
		go func(i int, v libunlynx.CipherText) {
			defer wg.Done()

			obfuscationSecret := libunlynx.SuiTe.Scalar().Pick(random.New())
			cipher := libunlynx.CipherText{}
			cipher.MulCipherTextbyScalar(v, obfuscationSecret)

			//proof
			proofsCs[i] = v
			proofsCos[i] = cipher
			proofsSs[i] = obfuscationSecret

			p.ToObfuscateData[i] = cipher

		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	if p.Proofs == 1 {
		go func() {
			proof := libdrynx.ObfuscationListProofCreation(proofsCs, proofsCos, proofsSs)
			pi := p.MapPIs["obfuscation/"+p.ServerIdentity().String()]
			pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{ObfuscationProof: libdrynx.NewObfuscationProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}

			go pi.Dispatch()
			go pi.Start()
			<-pi.(*ProofCollectionProtocol).FeedbackChannel
		}()
	}

	if !p.IsLeaf() {

		length := make([]ObfuscationLengthStruct, 0)
		for _, v := range <-p.LengthNodeChannel {
			length = append(length, v)
		}
		datas := make([]ObfuscationUpBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}
		for i, v := range length {
			childrenContribution := libunlynx.NewCipherVector(v.Length)
			childrenContribution.FromBytes(datas[i].Data, v.Length)

			//roundComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Aggregation)")

			p.ToObfuscateData.Add(p.ToObfuscateData, *childrenContribution)

			//libunlynx.EndTimer(roundComput)
		}
	}

	//libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {

		p.SendToParent(&ObfuscationLengthMessage{len(p.ToObfuscateData)})
		message, _ := (p.ToObfuscateData).ToBytes()
		p.SendToParent(&ObfuscationUpBytesMessage{Data: message})
	}

	return p.ToObfuscateData
}
