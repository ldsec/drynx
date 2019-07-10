package protocols

import (
	"errors"
	"fmt"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/lib/proof"
	"github.com/lca1/drynx/lib/range"
	"github.com/lca1/unlynx/data"
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"math/rand"
	"sync"
)

// DataCollectionProtocolName is the registered name for the data provider protocol.
const DataCollectionProtocolName = "DataCollection"

var mutexGroups sync.Mutex

func init() {
	network.RegisterMessage(AnnouncementDCMessage{})
	network.RegisterMessage(DataCollectionMessage{})
	if _, err := onet.GlobalProtocolRegister(DataCollectionProtocolName, NewDataCollectionProtocol); err != nil {
		log.Fatal("Error registering <DataCollectionProtocol>:", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// AnnouncementDCMessage message sent (with the query) to trigger a data collection protocol.
type AnnouncementDCMessage struct{}

// DataCollectionMessage message that contains the data of each data provider
type DataCollectionMessage struct {
	DCMdata libdrynx.ResponseDPBytes
}

// Structs
//______________________________________________________________________________________________________________________

// SurveyToDP is used to trigger the upload of data by a data provider
type SurveyToDP struct {
	SurveyID  string
	Aggregate kyber.Point // the joint aggregate key to encrypt the data

	// query statement
	Query libdrynx.Query // the query must be added to each node before the protocol can start
}

// AnnouncementDCStruct announcement message
type AnnouncementDCStruct struct {
	*onet.TreeNode
	AnnouncementDCMessage
}

// DataCollectionStruct is the wrapper of DataCollectionMessage to be used in a channel
type DataCollectionStruct struct {
	*onet.TreeNode
	DataCollectionMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// DataCollectionProtocol hold the state of a data provider protocol instance.
type DataCollectionProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan map[string]libunlynx.CipherVector //map containing the aggregation of all data providers' responses

	// Protocol communication channels
	AnnouncementChannel   chan AnnouncementDCStruct
	DataCollectionChannel chan DataCollectionStruct

	// Protocol state data
	Survey SurveyToDP

	// Protocol proof data
	MapPIs map[string]onet.ProtocolInstance
}

// NewDataCollectionProtocol constructs a DataCollection protocol instance.
func NewDataCollectionProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dcp := &DataCollectionProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan map[string]libunlynx.CipherVector),
	}

	err := dcp.RegisterChannel(&dcp.AnnouncementChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = dcp.RegisterChannel(&dcp.DataCollectionChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return dcp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *DataCollectionProtocol) Start() error {
	log.Lvl2("["+p.Name()+"]", "starts a Data Collection Protocol.")

	for _, node := range p.Tree().List() {
		// the root node sends an announcement message to all the nodes
		if !node.IsRoot() {
			if err := p.SendTo(node, &AnnouncementDCMessage{}); err != nil {
				log.Fatal(err)
			}
		}
	}
	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DataCollectionProtocol) Dispatch() error {
	defer p.Done()

	// 1. If not root -> wait for announcement message from root
	if !p.IsRoot() {
		response, err := p.GenerateData()
		if err != nil {
			log.Fatal(err)
		}

		dcm := DataCollectionMessage{DCMdata: response}

		// 2. Send data to root
		if err := p.SendTo(p.Root(), &dcm); err != nil {
			return err
		}
	} else {
		// 3. If root wait for all other nodes to send their data
		dcmAggregate := make(map[string]libunlynx.CipherVector, 0)
		for i := 0; i < len(p.Tree().List())-1; i++ {
			dcm := <-p.DataCollectionChannel
			dcmData := dcm.DCMdata

			// received map with bytes -> go back to map with CipherVector
			dcmDecoded := make(map[string]libunlynx.CipherVector, len(dcmData.Data))
			for i, v := range dcmData.Data {
				cv := libunlynx.NewCipherVector(dcmData.Len)
				cv.FromBytes(v, dcmData.Len)
				dcmDecoded[i] = *cv
			}

			// aggregate values that belong to the same group (that are originated from different data providers)
			for key, value := range dcmDecoded {
				// if already in the map -> add to what is inside
				if cv, ok := dcmAggregate[key]; ok {
					newCV := libunlynx.NewCipherVector(len(cv))
					newCV.Add(cv, value)
					dcmAggregate[key] = *newCV
				} else { // otherwise create a new entry
					dcmAggregate[key] = value
				}
			}
		}
		p.FeedbackChannel <- dcmAggregate
	}
	return nil
}

// Support Functions
//______________________________________________________________________________________________________________________

// GenerateData is used to generate data at DPs, this is more for simulation's purposes
func (p *DataCollectionProtocol) GenerateData() (libdrynx.ResponseDPBytes, error) {

	// Prepare the generation of all possible groups with the query information.
	numType := make([]int64, len(p.Survey.Query.DPDataGen.GroupByValues))
	for i, v := range p.Survey.Query.DPDataGen.GroupByValues {
		numType[i] = v
	}
	mutexGroups.Lock()

	groups := make([][]int64, 0)
	group := make([]int64, 0)
	dataunlynx.AllPossibleGroups(numType[:], group, 0, &groups)
	groupsString := make([]string, len(groups))

	for i, v := range groups {
		groupsString[i] = fmt.Sprint(v)
	}
	mutexGroups.Unlock()
	// read the signatures needed to compute the range proofs
	signatures := make([][]libdrynx.PublishSignature, p.Survey.Query.IVSigs.InputValidationSize1)
	for i := 0; i < p.Survey.Query.IVSigs.InputValidationSize1; i++ {
		signatures[i] = make([]libdrynx.PublishSignature, p.Survey.Query.IVSigs.InputValidationSize2)
		for j := 0; j < p.Survey.Query.IVSigs.InputValidationSize2; j++ {
			signatures[i][j] = libdrynxrange.PublishSignatureBytesToPublishSignatures((*p.Survey.Query.IVSigs.InputValidationSigs[i])[j])
		}
	}

	// generate fake random data depending on the operation
	fakeData := createFakeDataForOperation(p.Survey.Query.Operation, p.Survey.Query.DPDataGen.GenerateRows, p.Survey.Query.DPDataGen.GenerateDataMin, p.Survey.Query.DPDataGen.GenerateDataMax)

	// logistic regression specific
	var xFloat [][]float64
	var yInt []int64
	lrParameters := p.Survey.Query.Operation.LRParameters
	if p.Survey.Query.Operation.NameOp == "logistic regression" {
		if lrParameters.FilePath != "" {
			// note: GetDataForDataProvider(...) business only for testing purpose
			dataProviderID := p.TreeNode().ServerIdentity
			xFloat, yInt = libdrynxencoding.GetDataForDataProvider(p.Survey.Query.Operation.LRParameters.DatasetName, p.Survey.Query.Operation.LRParameters.FilePath, *dataProviderID)

			// set the number of records to the number of records owned by this data provider
			//dataSpecifics = recq.Query.Operation.DataSpecifics
			lrParameters.NbrRecords = int64(len(xFloat))
		} else {
			// create dummy data
			xFloat = make([][]float64, lrParameters.NbrRecords)
			yInt = make([]int64, lrParameters.NbrRecords)
			limit := 4

			m := int(lrParameters.NbrFeatures)
			for i := 0; i < int(lrParameters.NbrRecords); i++ {
				xFloat[i] = make([]float64, m)
				yInt[i] = int64(rand.Intn(2)) // sample 0 or 1 randomly for the label
				for j := 1; j < m; j++ {
					r := rand.Intn(limit)
					xFloat[i][j] = float64(r)
				}
			}
		}
	}

	// ------- START: ENCODING & ENCRYPTION -------
	//encodeTime := libunlynx.StartTimer(p.Name() + "_DPencoding")
	cprf := make([]libdrynxrange.CreateProof, 0)

	// compute response
	queryResponse := make(map[string]libunlynx.CipherVector, 0)
	clearResponse := make([]int64, 0)
	encryptedResponse := make([]libunlynx.CipherText, 0)

	// for all different groups
	for _, v := range groupsString {
		if p.Survey.Query.CuttingFactor != 0 {
			p.Survey.Query.Operation.NbrOutput = int(p.Survey.Query.Operation.NbrOutput / p.Survey.Query.CuttingFactor)
		}
		if p.Survey.Query.Operation.NameOp == "logistic regression" {
			//p.Survey.Query.Ranges = nil
			encryptedResponse, clearResponse, cprf = libdrynxencoding.EncodeForFloat(xFloat, yInt, lrParameters, p.Survey.Aggregate, signatures, p.Survey.Query.Ranges, p.Survey.Query.Operation.NameOp)
		} else {
			encryptedResponse, clearResponse, cprf = libdrynxencoding.Encode(fakeData, p.Survey.Aggregate, signatures, p.Survey.Query.Ranges, p.Survey.Query.Operation)
		}

		log.Lvl2("Data Provider", p.Name(), "computes the query response", clearResponse, "for groups:", groupsString, "with operation:", p.Survey.Query.Operation)

		queryResponse[v] = libunlynx.CipherVector(encryptedResponse)

		// scaling for simulation purposes
		qr := queryResponse[v]
		for i := 0; i < p.Survey.Query.CuttingFactor-1; i++ {
			queryResponse[v] = append(queryResponse[v], qr...)
		}
		if p.Survey.Query.Proofs != 0 {
			go func() {
				startAllProofs := libunlynx.StartTimer(p.Name() + "_AllProofs")
				rpl := libdrynxrange.RangeProofList{}

				//rangeProofCreation := libunlynx.StartTimer(p.Name() + "_RangeProofCreation")
				// no range proofs (send only the ciphertexts)
				if len(cprf) == 0 {
					tmp := make([]libdrynxrange.RangeProof, 0)
					for _, ct := range queryResponse[v] {
						tmp = append(tmp, libdrynxrange.RangeProof{Commit: ct, RP: nil})
					}
					rpl = libdrynxrange.RangeProofList{Data: tmp}
				} else { // if range proofs
					rpl = libdrynxrange.RangeProofList{Data: libdrynxrange.CreatePredicateRangeProofListForAllServers(cprf)}
				}
				// scaling for simulation purposes
				if p.Survey.Query.CuttingFactor != 0 {
					rplNew := libdrynxrange.RangeProofList{}
					rplNew.Data = make([]libdrynxrange.RangeProof, len(rpl.Data)*p.Survey.Query.CuttingFactor)
					counter := 0
					suitePair := bn256.NewSuite()
					for j := 0; j < p.Survey.Query.CuttingFactor; j++ {
						for _, v := range rpl.Data {

							rplNew.Data[counter].RP = &libdrynxrange.RangeProofData{}
							rplNew.Data[counter].RP.V = make([][]kyber.Point, len(v.RP.V))
							for k, w := range v.RP.V {
								rplNew.Data[counter].RP.V[k] = make([]kyber.Point, len(w))
								for l, x := range w {
									tmp := suitePair.G2().Point().Null()
									tmp.Add(tmp, x)
									rplNew.Data[counter].RP.V[k][l] = tmp
								}
							}
							//rplNew.Data[counter].RP.V = tmp.Add(tmp,v.RP.V)
							rplNew.Data[counter].RP.Zv = v.RP.Zv
							rplNew.Data[counter].RP.Zr = v.RP.Zr
							rplNew.Data[counter].RP.Challenge = v.RP.Challenge
							rplNew.Data[counter].RP.D = v.RP.D
							rplNew.Data[counter].RP.Zphi = v.RP.Zphi
							rplNew.Data[counter].RP.A = v.RP.A
							//rplNew.Data[counter].RP. = &newRpd
							rplNew.Data[counter].Commit = v.Commit
							counter = counter + 1
						}
					}

					rpl.Data = rplNew.Data
				}

				pi := p.MapPIs["range/"+p.ServerIdentity().String()]
				pi.(*ProofCollectionProtocol).Proof = drynxproof.ProofRequest{RangeProof: drynxproof.NewRangeProofRequest(&rpl, p.Survey.SurveyID, p.ServerIdentity().String(), "", p.Survey.Query.RosterVNs, p.Private(), nil)}
				//libunlynx.EndTimer(rangeProofCreation)

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

				libunlynx.EndTimer(startAllProofs)

			}()
		}
	}
	//libunlynx.EndTimer(encodeTime)
	// ------- END -------

	//convert the response to bytes
	length := len(queryResponse)
	queryResponseBytes := make(map[string][]byte, length)
	lenQueryResponse := 0
	wg := libunlynx.StartParallelize(length)
	mutex := sync.Mutex{}
	for i, v := range queryResponse {
		go func(group string, cv libunlynx.CipherVector) {
			defer wg.Done()
			cvBytes, lenQ, _ := cv.ToBytes()

			mutex.Lock()
			lenQueryResponse = lenQ
			queryResponseBytes[group] = cvBytes
			mutex.Unlock()
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	return libdrynx.ResponseDPBytes{Data: queryResponseBytes, Len: lenQueryResponse}, nil
}

// createFakeDataForOperation creates fake data to be used
func createFakeDataForOperation(operation libdrynx.Operation, nbrRows, min, max int64) [][]int64 {
	//either use the min and max defined by the query or the default constants
	zero := int64(0)
	if min == zero && max == zero {
		log.Lvl2("Only generating 0s!")
	}

	//generate response tab
	tab := make([][]int64, operation.NbrInput)
	wg := libunlynx.StartParallelize(len(tab))
	for i := range tab {
		go func(i int) {
			defer wg.Done()
			tab[i] = dataunlynx.CreateInt64Slice(nbrRows, min, max)
		}(i)

	}
	libunlynx.EndParallelize(wg)
	return tab
}
