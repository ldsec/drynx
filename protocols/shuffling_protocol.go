// Shuffling protocol which permits to rerandomize and shuffle a list of DP responses.
// The El-Gamal encrypted DP response should be encrypted by the collective public key of the cothority.
// In that case, each cothority server (node) can  homomorphically rerandomize and shuffle the DP responses.
// This is done by creating a circuit between the servers. The DP response is sent through this circuit and
// each server applies its transformation on it and forwards it to the next node in the circuit
// until it comes back to the server who started the protocol.
package protocols

import (
	"errors"

	"time"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
)

// ShufflingProtocolName is the registered name for the neff shuffle protocol.
const ShufflingProtocolName = "Shuffling"

func init() {
	network.RegisterMessage(libdrynx.ShufflingMessage{})
	network.RegisterMessage(libdrynx.ShufflingBytesMessage{})
	network.RegisterMessage(SBLengthMessage{})
	onet.GlobalProtocolRegister(ShufflingProtocolName, NewShufflingProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// SBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type SBLengthMessage struct {
	Sender      string
	GacbLength  int
	AabLength   int
	PgaebLength int
}

// Structs
//______________________________________________________________________________________________________________________

// ShufflingBytesStruct contains a shuffling message in bytes
type shufflingBytesStruct struct {
	*onet.TreeNode
	libdrynx.ShufflingBytesMessage
}

// SbLengthStruct contains a length message
type sbLengthStruct struct {
	*onet.TreeNode
	SBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingProtocol hold the state of a shuffling protocol instance.
type ShufflingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.ProcessResponse

	// Protocol communication channels
	LengthNodeChannel         chan sbLengthStruct
	PreviousNodeInPathChannel chan shufflingBytesStruct

	ExecTimeStart time.Duration
	ExecTime      time.Duration

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfShuffle   *[]libunlynx.ProcessResponse

	CollectiveKey kyber.Point //only use in order to test the protocol
	Proofs        int
	Precomputed   []libunlynx.CipherVectorScalar

	Query *libdrynx.SurveyQuery

	// Protocol proof data
	MapPIs map[string]onet.ProtocolInstance
}

// NewShufflingProtocol constructs neff shuffle protocol instances.
func NewShufflingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &ShufflingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.ProcessResponse),
	}

	if err := dsp.RegisterChannel(&dsp.PreviousNodeInPathChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	if err := dsp.RegisterChannel(&dsp.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	var i int
	var node *onet.TreeNode
	var nodeList = n.Tree().List()
	for i, node = range nodeList {
		if n.TreeNode().Equal(node) {
			dsp.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}
	return dsp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ShufflingProtocol) Start() error {

	roundTotalStart := libunlynx.StartTimer(p.Name() + "_Shuffling(START)")

	if p.TargetOfShuffle == nil {
		return errors.New("no map given as shuffling target")
	}

	p.ExecTimeStart = 0
	p.ExecTime = 0
	startT := time.Now()

	nbrProcessResponses := len(*p.TargetOfShuffle)
	log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " started a Shuffling Protocol (", nbrProcessResponses, " responses)")

	shuffleTarget := *p.TargetOfShuffle

	if len(shuffleTarget) == 1 { //cannot shuffle 1 -> add a dummy response with 0s
		pr := libunlynx.ProcessResponse{}
		pr.GroupByEnc = shuffleTarget[0].GroupByEnc
		pr.WhereEnc = shuffleTarget[0].WhereEnc
		pr.AggregatingAttributes = make(libunlynx.CipherVector, len(shuffleTarget[0].AggregatingAttributes))
		for i := range shuffleTarget[0].AggregatingAttributes {
			pr.AggregatingAttributes[i] = libunlynx.IntToCipherText(int64(0))
		}
		shuffleTarget = append(shuffleTarget, pr)
	}

	collectiveKey := p.Roster().Aggregate
	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.Lvl2("Key used is ", collectiveKey)
	}
	roundShufflingStart := libunlynx.StartTimer(p.Name() + "_Shuffling(START-noProof)")

	if p.Precomputed != nil {
		log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " uses pre-computation in shuffling")
	}

	shuffledData, pi, beta := libdrynx.ShuffleSequence(shuffleTarget, nil, collectiveKey, p.Precomputed)
	libunlynx.EndTimer(roundShufflingStart)
	roundShufflingStartProof := libunlynx.StartTimer(p.Name() + "_Shuffling(START-Proof)")

	if p.Proofs != 0 {
		go func() {
			log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), "creates shuffling proof")
			proof := libdrynx.ShufflingProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)

			pi := p.MapPIs["shuffle/"+p.ServerIdentity().String()]
			pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{ShuffleProof: libdrynx.NewShuffleProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}
			go pi.Dispatch()
			go pi.Start()
			<-pi.(*ProofCollectionProtocol).FeedbackChannel
		}()
	}

	libunlynx.EndTimer(roundShufflingStartProof)
	libunlynx.EndTimer(roundTotalStart)

	p.ExecTimeStart += time.Since(startT)
	//sendingStart := libdrynx.StartTimer(p.Name() + "_Sending")

	message := libdrynx.ShufflingBytesMessage{}
	var cgaLength, eaaLength, egaLength int
	message.Data, cgaLength, eaaLength, egaLength = (&libdrynx.ShufflingMessage{Data: shuffledData}).ToBytes()

	sendingStart := libunlynx.StartTimer(p.Name() + "_Sending")

	p.sendToNext(&SBLengthMessage{p.ServerIdentity().String(), cgaLength, eaaLength, egaLength})
	p.sendToNext(&message)

	libunlynx.EndTimer(sendingStart)

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingProtocol) Dispatch() error {
	defer p.Done()

	shufflingLength := <-p.LengthNodeChannel

	receiving := libunlynx.StartTimer(p.Name() + "_Receiving")
	tmp := <-p.PreviousNodeInPathChannel

	libunlynx.EndTimer(receiving)

	sm := libdrynx.ShufflingMessage{}
	sm.FromBytes(tmp.Data, shufflingLength.GacbLength, shufflingLength.AabLength, shufflingLength.PgaebLength)
	shufflingTarget := sm.Data

	startT := time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH)")

	collectiveKey := p.Roster().Aggregate //shuffling is by default done with collective authority key

	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.Lvl2("Key used: ", collectiveKey)
	}

	if p.Precomputed != nil {
		log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " uses pre-computation in shuffling")
	}

	shuffledData := shufflingTarget
	var pi []int
	var beta [][]kyber.Scalar

	if !p.IsRoot() {
		roundShuffle := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-noProof)")

		shuffledData, pi, beta = libdrynx.ShuffleSequence(shufflingTarget, nil, collectiveKey, p.Precomputed)

		libunlynx.EndTimer(roundShuffle)
		roundShuffleProof := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-Proof)")

		if p.Proofs != 0 {
			go func(shufflingTarget []libunlynx.ProcessResponse, shuffledData []libunlynx.ProcessResponse) {
				log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), "creates shuffling proof")
				proof := libdrynx.ShufflingProofCreation(shufflingTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)

				pi := p.MapPIs["shuffle/"+p.ServerIdentity().String()]
				pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{ShuffleProof: libdrynx.NewShuffleProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}
				go pi.Dispatch()
				go pi.Start()
				<-pi.(*ProofCollectionProtocol).FeedbackChannel
			}(shufflingTarget, shuffledData)

		}
		libunlynx.EndTimer(roundShuffleProof)

	}
	shufflingTarget = shuffledData

	if p.IsRoot() {
		log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " completed shuffling (", len(shufflingTarget), " responses)")
	} else {
		log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " carried on shuffling.")
	}

	libunlynx.EndTimer(roundTotalComputation)

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
		p.FeedbackChannel <- shufflingTarget
	} else {
		message := libdrynx.ShufflingBytesMessage{}
		var cgaLength, eaaLength, egaLength int
		message.Data, cgaLength, eaaLength, egaLength = (&libdrynx.ShufflingMessage{Data: shuffledData}).ToBytes()

		sending := libunlynx.StartTimer(p.Name() + "_Sending")

		p.sendToNext(&SBLengthMessage{p.ServerIdentity().String(), cgaLength, eaaLength, egaLength})
		p.sendToNext(&message)

		libunlynx.EndTimer(sending)
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *ShufflingProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl2("Had an error sending a message: ", err)
	}
}

// Conversion
//______________________________________________________________________________________________________________________
