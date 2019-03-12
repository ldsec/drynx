// The collective aggregation protocol permits the cothority to collectively aggregate the local
// results of all the servers.
// It uses the tree structure of the cothority. The root sends down an aggregation trigger message. The leafs
// respond with their local result and other nodes aggregate what they receive before forwarding the
// aggregation result up the tree until the root can produce the final result.

package protocols

import (
	"errors"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/unlynx/lib"
	"sync"
)

// CollectiveAggregationProtocolName is the registered name for the collective aggregation protocol.
const CollectiveAggregationProtocolName = "CollectiveAggregation"

func init() {
	network.RegisterMessage(DataReferenceMessage{})
	network.RegisterMessage(ChildAggregatedDataMessage{})
	network.RegisterMessage(ChildAggregatedDataBytesMessage{})
	network.RegisterMessage(CADBLengthMessage{})
	onet.GlobalProtocolRegister(CollectiveAggregationProtocolName, NewCollectiveAggregationProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// DataReferenceMessage message sent to trigger an aggregation protocol.
type DataReferenceMessage struct{}

// ChildAggregatedDataMessage contains one node's aggregated data.
type ChildAggregatedDataMessage struct {
	ChildData []libunlynx.FilteredResponseDet
}

// ChildAggregatedDataBytesMessage is ChildAggregatedDataMessage in bytes.
type ChildAggregatedDataBytesMessage struct {
	Data []byte
}

// CADBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type CADBLengthMessage struct {
	GacbLength int
	AabLength  int
	DtbLength  int
}

// Structs
//______________________________________________________________________________________________________________________

type dataReferenceStruct struct {
	*onet.TreeNode
	DataReferenceMessage
}

type childAggregatedDataBytesStruct struct {
	*onet.TreeNode
	ChildAggregatedDataBytesMessage
}

type cadmbLengthStruct struct {
	*onet.TreeNode
	CADBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// CollectiveAggregationProtocol performs an aggregation of the data held by every node in the cothority.
type CollectiveAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan libdrynx.CothorityAggregatedData

	// Protocol communication channels
	DataReferenceChannel chan dataReferenceStruct
	LengthNodeChannel    chan []cadmbLengthStruct
	ChildDataChannel     chan []childAggregatedDataBytesStruct

	// Protocol state data
	GroupedData *map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// NewCollectiveAggregationProtocol initializes the protocol instance.
func NewCollectiveAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pap := &CollectiveAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libdrynx.CothorityAggregatedData),
	}

	err := pap.RegisterChannel(&pap.DataReferenceChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = pap.RegisterChannel(&pap.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register child-data channel: " + err.Error())
	}

	if err := pap.RegisterChannel(&pap.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return pap, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *CollectiveAggregationProtocol) Start() error {
	if p.GroupedData == nil {
		return errors.New("no data reference provided for aggregation")
	}
	log.Lvl2("[COLLECTIVE AGGREGATION PROTOCOL] <Drynx> Server", p.ServerIdentity(), " started a Collective Aggregation Protocol (", len(*p.GroupedData), "local group(s) )")
	p.SendToChildren(&DataReferenceMessage{})
	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *CollectiveAggregationProtocol) Dispatch() error {
	defer p.Done()

	// 1. Aggregation announcement phase
	if !p.IsRoot() {
		p.aggregationAnnouncementPhase()
	}

	// 2. Ascending aggregation phase
	aggregatedData := p.ascendingAggregationPhase()
	log.Lvl2("[COLLECTIVE AGGREGATION PROTOCOL] <Drynx> Server", p.ServerIdentity(), " completed aggregation phase (", len(*aggregatedData), "group(s) )")

	// 3. Response reporting
	if p.IsRoot() {
		p.FeedbackChannel <- libdrynx.CothorityAggregatedData{GroupedData: *aggregatedData}
	}
	return nil
}

// Announce forwarding down the tree.
func (p *CollectiveAggregationProtocol) aggregationAnnouncementPhase() {
	dataReferenceMessage := <-p.DataReferenceChannel
	if !p.IsLeaf() {
		p.SendToChildren(&dataReferenceMessage.DataReferenceMessage)
	}
}

// Results pushing up the tree containing aggregation results.
func (p *CollectiveAggregationProtocol) ascendingAggregationPhase() *map[libunlynx.GroupingKey]libunlynx.FilteredResponse {

	if p.GroupedData == nil {
		emptyMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse, 0)
		p.GroupedData = &emptyMap
	}

	//roundTotComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(ascendingAggregation)")

	if !p.IsLeaf() {

		length := make([]cadmbLengthStruct, 0)
		for _, v := range <-p.LengthNodeChannel {
			length = append(length, v)
		}
		datas := make([]childAggregatedDataBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}
		for i, v := range length {
			childrenContribution := ChildAggregatedDataMessage{}
			childrenContribution.FromBytes(datas[i].Data, v.GacbLength, v.AabLength, v.DtbLength)

			//roundComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Aggregation)")

			for _, aggr := range childrenContribution.ChildData {
				localAggr, ok := (*p.GroupedData)[aggr.DetTagGroupBy]
				if ok {
					tmp := libunlynx.NewCipherVector(len(localAggr.AggregatingAttributes))
					tmp.Add(localAggr.AggregatingAttributes, aggr.Fr.AggregatingAttributes)

					localAggr.AggregatingAttributes = *tmp
				} else {
					localAggr = aggr.Fr
				}
				(*p.GroupedData)[aggr.DetTagGroupBy] = localAggr
			}

			//libunlynx.EndTimer(roundComput)
		}
	}

	//libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {
		detAggrResponses := make([]libunlynx.FilteredResponseDet, len(*p.GroupedData))
		count := 0
		for i, v := range *p.GroupedData {
			detAggrResponses[count].DetTagGroupBy = i
			detAggrResponses[count].Fr = v
			count++
		}

		message := ChildAggregatedDataBytesMessage{}

		var gacbLength, aabLength, dtbLength int

		message.Data, gacbLength, aabLength, dtbLength = (&ChildAggregatedDataMessage{detAggrResponses}).ToBytes()
		childrenContribution := ChildAggregatedDataMessage{}
		childrenContribution.FromBytes(message.Data, gacbLength, aabLength, dtbLength)

		p.SendToParent(&CADBLengthMessage{gacbLength, aabLength, dtbLength})
		p.SendToParent(&message)
	}

	return p.GroupedData
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a ChildAggregatedDataMessage to a byte array
func (sm *ChildAggregatedDataMessage) ToBytes() ([]byte, int, int, int) {

	b := make([]byte, 0)
	bb := make([][]byte, len((*sm).ChildData))

	var gacbLength int
	var aabLength int
	//var pgaebLength int
	var dtbLength int

	wg := libunlynx.StartParallelize(len((*sm).ChildData))
	var mutexCD sync.Mutex
	for i := range (*sm).ChildData {
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexCD.Lock()
				data := (*sm).ChildData[i]
				mutexCD.Unlock()

				aux, gacbAux, aabAux, dtbAux := data.ToBytes()

				mutexCD.Lock()
				bb[i] = aux
				gacbLength = gacbAux
				aabLength = aabAux
				dtbLength = dtbAux
				mutexCD.Unlock()

			}(i)
		} else {
			bb[i], gacbLength, aabLength, dtbLength = (*sm).ChildData[i].ToBytes()
		}

	}
	libunlynx.EndParallelize(wg)

	for _, el := range bb {
		b = append(b, el...)
	}
	return b, gacbLength, aabLength, dtbLength
}

// FromBytes converts a byte array to a ChildAggregatedDataMessage. Note that you need to create the (empty) object beforehand.
func (sm *ChildAggregatedDataMessage) FromBytes(data []byte, gacbLength, aabLength, dtbLength int) {
	lengthCipher := libunlynx.SuiTe.PointLen() * 2
	elementLength := gacbLength*lengthCipher + aabLength*lengthCipher + dtbLength //CAUTION: hardcoded 64 (size of el-gamal element C,K)

	if elementLength != 0 && len(data) > 0 {
		var nbrChildData int
		nbrChildData = len(data) / elementLength

		(*sm).ChildData = make([]libunlynx.FilteredResponseDet, nbrChildData)
		wg := libunlynx.StartParallelize(nbrChildData)
		for i := 0; i < nbrChildData; i++ {
			v := data[i*elementLength : i*elementLength+elementLength]
			if libunlynx.PARALLELIZE {
				go func(v []byte, i int) {
					defer wg.Done()
					(*sm).ChildData[i].FromBytes(v, gacbLength, aabLength, dtbLength)
				}(v, i)
			} else {
				(*sm).ChildData[i].FromBytes(v, gacbLength, aabLength, dtbLength)
			}

		}
		libunlynx.EndParallelize(wg)
	}
}
