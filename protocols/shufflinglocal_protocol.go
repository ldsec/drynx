// Package protocols contains Shuffling Local protocol.
// This protocol is the first try to improve the shuffling protocol by better distributing the workload
package protocols

import (
	"errors"

	"time"

	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"sync"
)

// ShufflingLocalProtocolName is the registered name for the improvment draft of the neff shuffle protocol.
const ShufflingLocalProtocolName = "ShufflingLocal"

func init() {
	network.RegisterMessage(ShufflingLocalMessage{})
	onet.GlobalProtocolRegister(ShufflingLocalProtocolName, NewShufflingLocalProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// ShufflingLocalMessage is the empty messagesent to trigger local shuffling at CNs.
type ShufflingLocalMessage struct{}

// Structs
//______________________________________________________________________________________________________________________

// ShufflingLocalMessageStruct is the struct corresponding to the shuffling local message
type ShufflingLocalMessageStruct struct {
	*onet.TreeNode
	ShufflingLocalMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingLocalProtocol hold the state of a shuffling protocol instance.
type ShufflingLocalProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.ProcessResponse

	// Protocol communication channels
	PreviousNodeInPathChannel chan ShufflingLocalMessageStruct

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

// NewShufflingLocalProtocol constructs neff shuffle protocol instances.
func NewShufflingLocalProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &ShufflingLocalProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.ProcessResponse),
	}

	if err := dsp.RegisterChannel(&dsp.PreviousNodeInPathChannel); err != nil {
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
func (p *ShufflingLocalProtocol) Start() error {

	if p.TargetOfShuffle == nil {
		return errors.New("no map given as shuffling target")
	}

	p.sendToNext(&ShufflingLocalMessage{})

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingLocalProtocol) Dispatch() error {
	defer p.Done()

	<-p.PreviousNodeInPathChannel

	startT := time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH)")

	collectiveKey := p.Aggregate() //shuffling is by default done with collective authority key

	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.Lvl2("Key used: ", collectiveKey)
	}

	if p.Precomputed != nil {
		log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " uses pre-computation in shuffling")
	}

	shufflingTarget := *p.TargetOfShuffle
	shuffledData := []libunlynx.ProcessResponse{}
	var pi []int
	var beta [][]kyber.Scalar

	var wg *sync.WaitGroup
	mu := sync.Mutex{}
	tmp := []libunlynx.ProcessResponse{}
	if p.Proofs != 0 {
		wg = libunlynx.StartParallelize(1)
		go func(shufflingTarget []libunlynx.ProcessResponse, shuffledData []libunlynx.ProcessResponse) {

			// SHUFFLING
			roundShuffle := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-noProof)")

			shuffledData, pi, beta = libdrynx.ShuffleSequence(shufflingTarget, nil, collectiveKey, p.Precomputed)
			mu.Lock()
			tmp = shuffledData
			mu.Unlock()
			libunlynx.EndTimer(roundShuffle)
			roundShuffleProof := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-Proof)")

			// PROOF
			log.Lvl2("[SHUFFLING PROTOCOL] <Drynx> Server", p.ServerIdentity(), "creates shuffling proof")
			proof := libdrynx.ShufflingProofCreation(shufflingTarget, shuffledData, libdrynx.PairingSuite.Point().Base(), collectiveKey, beta, pi)
			wg.Done()

			pi := p.MapPIs["shuffle/"+p.ServerIdentity().String()]
			pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{ShuffleProof: libdrynx.NewShuffleProofRequest(&proof, p.Query.SurveyID, p.ServerIdentity().String(), "", p.Query.Query.RosterVNs, p.Private(), nil)}
			go pi.Dispatch()
			go pi.Start()
			<-pi.(*ProofCollectionProtocol).FeedbackChannel

			libunlynx.EndTimer(roundShuffleProof)

		}(shufflingTarget, shuffledData)

	}
	mu.Lock()
	shufflingTarget = tmp
	mu.Unlock()

	if p.IsRoot() {
		if wg != nil {
			libunlynx.EndParallelize(wg)
		}
		mu.Lock()
		shufflingTarget = tmp
		mu.Unlock()

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
		sending := libunlynx.StartTimer(p.Name() + "_Sending")

		p.sendToNext(&ShufflingLocalMessage{})

		libunlynx.EndTimer(sending)
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *ShufflingLocalProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl2("Had an error sending a message: ", err)
	}
}

// Conversion
//______________________________________________________________________________________________________________________
