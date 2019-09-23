// The collective aggregation protocol permits the cothority to collectively aggregate the local
// results of all the servers.
// It uses the tree structure of the cothority. The root sends down an aggregation trigger message. The leafs
// respond with their local result and other nodes aggregate what they receive before forwarding the
// aggregation result up the tree until the root can produce the final result.

package protocols

import (
	"errors"
	"github.com/ldsec/drynx/lib/obfuscation"
	"github.com/ldsec/drynx/lib/proof"

	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"sync"
)

// ObfuscationProtocolName is the registered name for the collective obfuscation protocol.
const ObfuscationProtocolName = "Obfuscation"

func init() {
	network.RegisterMessage(ObfuscationDownMessage{})
	network.RegisterMessage(ChildAggregatedDataMessage{})
	network.RegisterMessage(ObfuscationUpMessage{})
	network.RegisterMessage(ObfuscationLengthMessage{})
	if _, err := onet.GlobalProtocolRegister(ObfuscationProtocolName, NewObfuscationProtocol); err != nil {
		log.Fatal("Error registering <ObfuscationProtocol>:", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// ChildAggregatedDataMessage contains one node's aggregated data.
type ChildAggregatedDataMessage struct {
	ChildData []libunlynx.FilteredResponseDet
}

// ObfuscationDownMessage message sent to trigger an obfuscation protocol.
type ObfuscationDownMessage struct {
	Data libunlynx.CipherVector
}

// ObfuscationUpMessage message sent up the tree to execute obfuscation protocol.
type ObfuscationUpMessage struct {
	ChildData libunlynx.CipherVector
}

// ObfuscationUpBytesMessage is ObfuscationUpMessage in bytes.
type ObfuscationUpBytesMessage struct {
	Data []byte
}

// ObfuscationDownBytesMessage is ObfuscationDownMessage in bytes.
type ObfuscationDownBytesMessage struct {
	Data []byte
}

// ObfuscationLengthMessage is a message containing the length of a message in bytes
type ObfuscationLengthMessage struct {
	Length int
}

// Structs
//______________________________________________________________________________________________________________________

// ObfuscationDownStruct struct used to send message down the tree
type ObfuscationDownStruct struct {
	*onet.TreeNode
	ObfuscationDownMessage
}

// ObfuscationDownBytesStruct is ObfuscationDownStruct in bytes
type ObfuscationDownBytesStruct struct {
	*onet.TreeNode
	ObfuscationDownBytesMessage
}

// ObfuscationUpStruct struct used to send message up the tree
type ObfuscationUpStruct struct {
	*onet.TreeNode
	ObfuscationUpMessage
}

// ObfuscationUpBytesStruct is ObfuscationUpStruct in bytes
type ObfuscationUpBytesStruct struct {
	*onet.TreeNode
	ObfuscationUpBytesMessage
}

// ObfuscationLengthStruct struct to send Length message
type ObfuscationLengthStruct struct {
	*onet.TreeNode
	ObfuscationLengthMessage
}

// PrepareObfuscationProof struct containing information used to create an obfuscation proof
type PrepareObfuscationProof struct {
	C, Co libunlynx.CipherText
	S     kyber.Scalar
}

// Protocol
//______________________________________________________________________________________________________________________

// ObfuscationProtocol performs an obfuscation of the data held by a node in the cothority.
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

	MutexObf sync.Mutex
}

// NewObfuscationProtocol initializes the protocol instance.
func NewObfuscationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pop := &ObfuscationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libunlynx.CipherVector),
		MutexObf:         sync.Mutex{},
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
	p.MutexObf.Lock()
	if p.ToObfuscateData == nil {
		return errors.New("no data reference provided for aggregation")
	}
	log.Lvl2("[OBFUSCATION PROTOCOL] <Drynx> Server", p.ServerIdentity(), " started an Obfuscation Protocol (", len(p.ToObfuscateData), "ciphertext(s) )")
	bytesMessage, length, _ := p.ToObfuscateData.ToBytes()
	p.MutexObf.Unlock()

	if err := p.SendToChildren(&ObfuscationLengthMessage{Length: length}); err != nil {
		return err
	}
	if err := p.SendToChildren(&ObfuscationDownBytesMessage{bytesMessage}); err != nil {
		return err
	}
	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *ObfuscationProtocol) Dispatch() error {
	defer p.Done()

	// 1. Obfuscation announcement phase
	if !p.IsRoot() {
		if err := p.obfuscationAnnouncementPhase(); err != nil {
			return err
		}
	}
	// 2. Ascending obfuscation phase
	obfuscatededData, err := p.ascendingObfuscationPhase()
	if err != nil {
		return err
	}
	log.Lvl2("[OBFUSCATION PROTOCOL] <Drynx> Server", p.ServerIdentity(), " completed obfuscation phase (", len(obfuscatededData), "group(s) )")

	// 3. Response reporting
	if p.IsRoot() {
		p.FeedbackChannel <- obfuscatededData
	}
	return nil
}

// Announce forwarding down the tree.
func (p *ObfuscationProtocol) obfuscationAnnouncementPhase() error {
	lengthMessage := <-p.LengthNodeChannel
	dataReferenceMessage := <-p.DataReferenceChannel

	cv := *libunlynx.NewCipherVector(lengthMessage[0].Length)
	cv.FromBytes(dataReferenceMessage.Data, lengthMessage[0].Length)
	p.MutexObf.Lock()
	p.ToObfuscateData = cv
	p.MutexObf.Unlock()
	if !p.IsLeaf() {
		if err := p.SendToChildren(&ObfuscationLengthMessage{Length: lengthMessage[0].Length}); err != nil {
			return err
		}
		if err := p.SendToChildren(&ObfuscationDownBytesMessage{Data: dataReferenceMessage.Data}); err != nil {
			return err
		}
	}
	return nil
}

// Results pushing up the tree containing aggregation results.
func (p *ObfuscationProtocol) ascendingObfuscationPhase() (libunlynx.CipherVector, error) {

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
			p.MutexObf.Lock()
			p.ToObfuscateData[i] = cipher
			p.MutexObf.Unlock()

		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	if p.Proofs == 1 {
		go func() {
			proof := libdrynxobfuscation.ObfuscationListProofCreation(proofsCs, proofsCos, proofsSs)
			pi := p.MapPIs["obfuscation/"+p.ServerIdentity().String()]
			pi.(*ProofCollectionProtocol).Proof = drynxproof.ProofRequest{ObfuscationProof: drynxproof.NewObfuscationProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}

			go func() {
				if err := pi.Dispatch(); err != nil {
					log.Fatal(err)
				}
			}()
			go func() {
				if err := pi.Start(); err != nil {
					log.Fatal(err)
				}
			}()
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
			p.MutexObf.Lock()
			p.ToObfuscateData.Add(p.ToObfuscateData, *childrenContribution)
			p.MutexObf.Unlock()
			//libunlynx.EndTimer(roundComput)
		}
	}

	//libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {
		if err := p.SendToParent(&ObfuscationLengthMessage{len(p.ToObfuscateData)}); err != nil {
			return libunlynx.CipherVector{}, err
		}
		p.MutexObf.Lock()
		message, _, _ := (p.ToObfuscateData).ToBytes()
		p.MutexObf.Unlock()
		if err := p.SendToParent(&ObfuscationUpBytesMessage{Data: message}); err != nil {
			return libunlynx.CipherVector{}, err
		}
	}

	return p.ToObfuscateData, nil
}
