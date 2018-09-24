// The key switching protocol permits the cothority to collectively switch the encryption of a ciphertext from the
// collective key to another key.
// It uses the tree structure of the cothority. The root sends down a trigger message. The leafs
// respond with their contribution result and other nodes aggregate what they receive before forwarding the
// result up the tree until the root can produce the final result.

package protocols

import (
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
)

// KeySwitchingProtocolName is the registered name for the collective aggregation protocol.
const KeySwitchingProtocolName = "KeySwitching"

func init() {
	network.RegisterMessage(DownMessage{})
	network.RegisterMessage(DownMessageBytes{})
	network.RegisterMessage(UpMessage{})
	network.RegisterMessage(UpBytesMessage{})
	network.RegisterMessage(LengthMessage{})
	onet.GlobalProtocolRegister(KeySwitchingProtocolName, NewKeySwitchingProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// DownMessage message sent down the tree containing all the rB (left part of ciphertexts)
type DownMessage struct {
	NewKey kyber.Point
	Rbs    []kyber.Point
}

// DownMessageBytes message sent down the tree containing all the rB (left part of ciphertexts) in bytes
type DownMessageBytes struct {
	Data []byte
}

// UpMessage contains the ciphertext used by the servers to create their key switching contribution.
type UpMessage struct {
	ChildData []libunlynx.CipherText
}

// UpBytesMessage is UpMessage in bytes.
type UpBytesMessage struct {
	Data []byte
}

// LengthMessage is a message containing the length of a message in bytes
type LengthMessage struct {
	Length int
}

// Structs
//______________________________________________________________________________________________________________________

// DownBytesStruct struct used to send DownMessage(Bytes)
type DownBytesStruct struct {
	*onet.TreeNode
	DownMessageBytes
}

// UpBytesStruct struct used to send Up(Bytes)Message
type UpBytesStruct struct {
	*onet.TreeNode
	UpBytesMessage
}

// LengthStruct struct used to send LengthMessage
type LengthStruct struct {
	*onet.TreeNode
	LengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// KeySwitchingProtocol performs an aggregation of the data held by every node in the cothority.
type KeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan libunlynx.CipherVector

	// Protocol communication channels
	DownChannel      chan DownBytesStruct
	LengthChannel    chan []LengthStruct
	ChildDataChannel chan []UpBytesStruct

	// Protocol state data
	TargetOfSwitch  *libunlynx.CipherVector
	TargetPublicKey *kyber.Point
	Proofs          int
	Query           *libdrynx.SurveyQuery

	// Protocol root data
	NodeContribution *libunlynx.CipherVector

	// Protocol proof data
	MapPIs map[string]onet.ProtocolInstance
}

// NewKeySwitchingProtocol initializes the protocol instance.
func NewKeySwitchingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pap := &KeySwitchingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libunlynx.CipherVector),
	}

	err := pap.RegisterChannel(&pap.DownChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = pap.RegisterChannel(&pap.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register child-data channel: " + err.Error())
	}

	if err := pap.RegisterChannel(&pap.LengthChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return pap, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *KeySwitchingProtocol) Start() error {

	//startRound := libunlynx.StartTimer(p.Name() + "_KeySwitching(START)")

	if p.TargetOfSwitch == nil {
		return errors.New("no ciphertext given as key switching target")
	}

	if p.TargetPublicKey == nil {
		return errors.New("no new public key to be switched on provided")
	}

	log.Lvl2("[KEY SWITCHING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " started a Key Switching Protocol")

	// Initializes the target ciphertext and extract the original ephemeral keys.
	dataLength := len(*p.TargetOfSwitch)
	initialTab := make([]kyber.Point, dataLength+1)

	// put the target public key in first position
	initialTab[0] = *p.TargetPublicKey
	for i, v := range *p.TargetOfSwitch {
		initialTab[i+1] = v.K
	}

	// root does its key switching
	rootContribution := p.keySwitching(p.Public(), *p.TargetPublicKey, initialTab[1:], p.Private())
	p.NodeContribution = &rootContribution

	p.SendToChildren(&DownMessageBytes{Data: libunlynx.AbstractPointsToBytes(initialTab)})

	//libunlynx.EndTimer(startRound)
	return nil
}

func (p *KeySwitchingProtocol) keySwitching(pubKey, targetPubKey kyber.Point, rbs []kyber.Point, secretKey kyber.Scalar) libunlynx.CipherVector {
	//switchedCiphers := make(libunlynx.CipherVector, len(rbs))
	switchedCiphers, ks2s, rBNegs, vis := libdrynx.NewKeySwitching(targetPubKey, rbs, secretKey)

	if p.Proofs != 0 {
		go func() {
			proof := libdrynx.KeySwitchListProofCreation(pubKey, targetPubKey, secretKey, len(rbs), ks2s, rBNegs, vis)
			pi := p.MapPIs["keyswitch/"+p.ServerIdentity().String()]
			pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{KeySwitchProof: libdrynx.NewKeySwitchProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}
			go pi.Dispatch()
			go pi.Start()
			<-pi.(*ProofCollectionProtocol).FeedbackChannel
		}()
	}

	return switchedCiphers
}

// Dispatch is called at each node and handle incoming messages.
func (p *KeySwitchingProtocol) Dispatch() error {
	defer p.Done()

	// 1. Aggregation announcement phase
	if !p.IsRoot() {
		targetPublicKey, rbs := p.switchingAnnouncementPhase()
		tmp := p.keySwitching(p.Public(), targetPublicKey, rbs, p.Private())
		p.NodeContribution = &tmp
	} else {

	}

	// 2. Ascending aggregation phase
	p.ascendingSwitchingPhase()

	// 3. Response reporting
	if p.IsRoot() {
		ksCiphers := *libunlynx.NewCipherVector(len(*p.TargetOfSwitch))

		wg := libunlynx.StartParallelize(len(*p.TargetOfSwitch))
		for i, v := range *p.TargetOfSwitch {
			go func(i int, v libunlynx.CipherText) {
				defer wg.Done()
				ksCiphers[i].K = (*p.NodeContribution)[i].K
				ksCiphers[i].C = libunlynx.SuiTe.Point().Add((*p.NodeContribution)[i].C, v.C)
			}(i, v)
		}
		libunlynx.EndParallelize(wg)
		p.FeedbackChannel <- ksCiphers
	}
	return nil
}

// Announce forwarding down the tree.
func (p *KeySwitchingProtocol) switchingAnnouncementPhase() (kyber.Point, []kyber.Point) {
	dataReferenceMessage := <-p.DownChannel
	if !p.IsLeaf() {
		p.SendToChildren(&dataReferenceMessage.DownMessageBytes)
	}
	message := libunlynx.BytesToAbstractPoints(dataReferenceMessage.Data)

	return message[0], message[1:]
}

// Results pushing up the tree containing aggregation results.
func (p *KeySwitchingProtocol) ascendingSwitchingPhase() *libunlynx.CipherVector {

	//roundTotComput := libunlynx.StartTimer(p.Name() + "_KeySwitching(ascendingAggregation)")

	if !p.IsLeaf() {
		length := make([]LengthStruct, 0)
		for _, v := range <-p.LengthChannel {
			length = append(length, v)
		}

		datas := make([]UpBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}
		for i := range length { // len of length is number of children
			cv := libunlynx.CipherVector{}
			cv.FromBytes(datas[i].Data, length[i].Length)
			sumCv := libunlynx.NewCipherVector(len(cv))
			sumCv.Add(*p.NodeContribution, cv)
			p.NodeContribution = sumCv

		}
	}

	//libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {
		p.SendToParent(&LengthMessage{len(*p.NodeContribution)})
		message, _ := (*p.NodeContribution).ToBytes()
		p.SendToParent(&UpBytesMessage{Data: message})
	}

	return p.NodeContribution
}
