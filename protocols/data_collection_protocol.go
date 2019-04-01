package protocols

import (
	"errors"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/lib/encoding"
	"github.com/lca1/drynx/services/data"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/default/data"
	"math/rand"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DataCollectionProtocolName is the registered name for the data provider protocol.
const DataCollectionProtocolName = "DataCollection"

func init() {
	network.RegisterMessage(AnnouncementDCMessage{})
	network.RegisterMessage(DataCollectionMessage{})
	onet.GlobalProtocolRegister(DataCollectionProtocolName, NewDataCollectionProtocol)
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

	//Path of the DP's database along with the table name
	DBPath string
	TableName string
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
		p.SendTo(p.Root(), &dcm)
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

	groups := make([][]int64, 0)
	group := make([]int64, 0)
	data.AllPossibleGroups(numType[:], group, 0, &groups)
	groupsString := make([]string, len(groups))

	for i, v := range groups {
		groupsString[i] = fmt.Sprint(v)
	}
	groups = make([][]int64, 0)

	// read the signatures needed to compute the range proofs
	signatures := make([][]libdrynx.PublishSignature, p.Survey.Query.IVSigs.InputValidationSize1)
	for i := 0; int64(i) < p.Survey.Query.IVSigs.InputValidationSize1; i++ {
		signatures[i] = make([]libdrynx.PublishSignature, p.Survey.Query.IVSigs.InputValidationSize2)
		for j := 0; int64(j) < p.Survey.Query.IVSigs.InputValidationSize2; j++ {
			signatures[i][j] = libdrynx.PublishSignatureBytesToPublishSignatures((*p.Survey.Query.IVSigs.InputValidationSigs[i])[j])
		}
	}

	// ------- START: ENCODING & ENCRYPTION -------
	//encodeTime := libunlynx.StartTimer(p.Name() + "_DPencoding")
	cprf := make([]libdrynx.CreateProof, 0)

	// compute response
	queryResponse := make(map[string]libunlynx.CipherVector, 0)
	clearResponse := make([]int64, 0)
	encryptedResponse := make([]libunlynx.CipherText, 0)

	// for all different groups
	for _, v := range groupsString {
		if p.Survey.Query.CuttingFactor != 0 {
			p.Survey.Query.Operation.NbrOutput = p.Survey.Query.Operation.NbrOutput / int64(p.Survey.Query.CuttingFactor)
		}
		if p.Survey.Query.Operation.NameOp == "log_reg" {
			// logistic regression
			var datasFloat [][]float64
			var dimension int64
			lrParameters := p.Survey.Query.Operation.LRParameters
			if lrParameters.FilePath != "" {
				startDBLogReg := time.Now()
				/*//Use the following (commented) ine of code in case the DPs share the total training dataset
				//otherwise use the uncommented line (as it is now, in case of distributed training dataset)
				datasFloat = encoding.GetDataForDataProvider(p.Survey.Query.Operation.LRParameters.FilePath, *p.TreeNode().ServerIdentity, lrParameters.NbrDps)*/

				datasFloat, dimension = fetchDBDataLogReg(lrParameters)
				log.LLvl1("Actual DB Log Reg fetch took", time.Since(startDBLogReg))

				// set the number of records to the number of records owned by this data provider
				lrParameters.NbrRecords = int64(len(datasFloat))
				lrParameters.NbrFeatures = dimension - 1

			} else {
				// create dummy data
				datasFloat = make([][]float64, lrParameters.NbrRecords)
				limit := 4

				m := int(lrParameters.NbrFeatures) + 1
				for i := 0; i < int(lrParameters.NbrRecords); i++ {
					datasFloat[i] = make([]float64, m)
					r := rand.Intn(2) // sample 0 or 1 randomly for the label
					datasFloat[i][0] = float64(r)
					for j := 1; j < m; j++ {datasFloat[i][j] = float64(rand.Intn(limit))}
				}
			}
			startEncodingLogReg := time.Now()
			encryptedResponse, clearResponse, cprf = encoding.EncodeForFloat(datasFloat, lrParameters, p.Survey.Aggregate, signatures, p.Survey.Query.Ranges, p.Survey.Query.Operation.NameOp)
			log.LLvl1("Encoding of data Log Reg took", time.Since(startEncodingLogReg))
		} else {
			var dpData [][]int64
			if p.Survey.Query.DPDataGen.Source == 0 {
				dpData = createFakeDataForOperation(p.Survey.Query.Operation, p.Survey.Query.DPDataGen.GenerateRows, p.Survey.Query.DPDataGen.GenerateDataMin, p.Survey.Query.DPDataGen.GenerateDataMax)
			} else if p.Survey.Query.DPDataGen.Source == 1 {
				startDB := time.Now()
				// fetch data from db
				dpData = fetchDataFromDB(p.Survey.Query.Operation, p.DBPath, p.TableName)
				log.LLvl1("Actual DB fetch took", time.Since(startDB))
			}

			startEncryption := time.Now()
			encryptedResponse, clearResponse, cprf = encoding.Encode(dpData, p.Survey.Aggregate, signatures, p.Survey.Query.Ranges, p.Survey.Query.Operation)
			log.LLvl1("Encryption of data took", time.Since(startEncryption))
		}

		log.Lvl2("Data Provider", p.Name(), "computes the query response", clearResponse, "for groups:", groupsString, "with operation:", p.Survey.Query.Operation)

		queryResponse[v] = libunlynx.CipherVector(encryptedResponse)

		// scaling for simulation purposes
		qr := queryResponse[v]
		for i := 0; int64(i) < p.Survey.Query.CuttingFactor-1; i++ {queryResponse[v] = append(queryResponse[v], qr...)}
		if p.Survey.Query.Proofs != 0 {
			go func() {
				startProofs := time.Now()
				//startAllProofs := libunlynx.StartTimer(p.Name() + "_AllProofs")
				rpl := libdrynx.RangeProofList{}
				//rangeProofCreation := libunlynx.StartTimer(p.Name() + "_RangeProofCreation")
				rangeProofCreation := time.Now()
				// no range proofs (send only the ciphertexts)
				if len(cprf) == 0 {
					tmp := make([]libdrynx.RangeProof, 0)
					for _, ct := range queryResponse[v] {
						tmp = append(tmp, libdrynx.RangeProof{Commit: ct, RP: nil})
					}
					rpl = libdrynx.RangeProofList{Data: tmp}
				} else { // if range proofs
					rpl = libdrynx.RangeProofList{Data: libdrynx.CreatePredicateRangeProofListForAllServers(cprf)}
				}

				// scaling for simulation purposes
				if p.Survey.Query.CuttingFactor != 0 {
					rplNew := libdrynx.RangeProofList{}
					rplNew.Data = make([]libdrynx.RangeProof, int64(len(rpl.Data))*p.Survey.Query.CuttingFactor)
					counter := 0
					suitePair := bn256.NewSuite()
					for j := 0; int64(j) < p.Survey.Query.CuttingFactor; j++ {
						for _, v := range rpl.Data {
							rplNew.Data[counter].RP = &libdrynx.RangeProofData{}
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
				pi.(*ProofCollectionProtocol).Proof = libdrynx.ProofRequest{RangeProof: libdrynx.NewRangeProofRequest(&rpl, p.Survey.SurveyID, p.ServerIdentity().String(), "", p.Survey.Query.RosterVNs, p.Private(), nil)}
				log.LLvl1("Range Proof Size =", len(pi.(*ProofCollectionProtocol).Proof.RangeProof.Data) + len(pi.(*ProofCollectionProtocol).Proof.RangeProof.Signature))
				//libunlynx.EndTimer(rangeProofCreation)
				log.LLvl1("Range Proof Creation took", time.Since(rangeProofCreation))

				go pi.Dispatch()
				go pi.Start()
				<-pi.(*ProofCollectionProtocol).FeedbackChannel

				//libunlynx.EndTimer(startAllProofs)
				log.LLvl1("AllProofs took ", time.Since(startProofs))
			}()
		}
	}
	//libunlynx.EndTimer(encodeTime)
	log.LLvl1("Encrypting locally aggregated answer")

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
			cvBytes, lenQ := cv.ToBytes()

			mutex.Lock()
			lenQueryResponse = lenQ
			queryResponseBytes[group] = cvBytes
			mutex.Unlock()
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	return libdrynx.ResponseDPBytes{Data: queryResponseBytes, Len: lenQueryResponse}, nil
}

// fetchDataFromDB fetches the DPs' data from their databases
func fetchDataFromDB(operation libdrynx.Operation, dbLocation string, tableName string) [][]int64 {
	scriptFetchDataDB := "fetchDPData.py"
	//tableName1 := "Records"
	//dbLocation1 := "Client.db"
	//tableName2 := "Prescriptions"
	//dbLocation2 := "MedicalDispensation.db"

	log.LLvl1(dbLocation)

	if operation.NameOp == "lin_reg" {
		//Send "true" as an argument if the operation in question is linear regression
		//QueryMin and QueryMax are not useful in this case
		cmd := exec.Command("python3", scriptFetchDataDB, dbLocation, tableName, "true", operation.Attributes)

		out, err := cmd.Output()
		if err != nil {println(err.Error())}

		dpData := strings.Split(string(out), "\n")
		//Last entry of dpData is an empty line
		dpData = dpData[:len(dpData)-1]
		tab := make([][]int64, operation.NbrInput)

		values := strings.Split(strings.TrimSuffix(strings.TrimPrefix(dpData[0], "("), ")"), ", ")
		for j := range values {tab[j] = make([]int64, len(dpData))}

		wg := libunlynx.StartParallelize(len(dpData))
		for i, row := range dpData {
			go func(i int, row string) {
				defer wg.Done()
				rowValues := strings.Split(row, ", ")
				for j, val := range rowValues {
					val64, _ := strconv.ParseInt(val, 10, 64)
					tab[j][i] = val64
				}
			}(i, row)
		}
		libunlynx.EndParallelize(wg)
		return tab
	} else {
		//Send "false" as an argument if the operation in question is not linear regression
		cmd := exec.Command("python3", scriptFetchDataDB, dbLocation, tableName, "false", operation.Attributes,
			strconv.FormatInt(operation.QueryMin, 10), strconv.FormatInt(operation.QueryMax, 10))

		out, err := cmd.Output()
		if err != nil {println(err.Error())}

		dpData := strings.Split(string(out), "\n")
		dpValues := make([]int64, len(dpData)-1)

		wg := libunlynx.StartParallelize(len(dpValues))
		for i := range dpValues {
			go func(i int) {
				defer wg.Done()
				n, _ := strconv.ParseInt(dpData[i], 10, 64)
				dpValues[i] = n
			}(i)
		}
		libunlynx.EndParallelize(wg)

		tab := make([][]int64, operation.NbrInput)
		tab[0] = dpValues
		return tab
	}
}

// fetchDBDataLogReg fetches the DPs' data from their databases for the logistic regression operation
func fetchDBDataLogReg(lrParameters libdrynx.LogisticRegressionParameters) ([][]float64, int64) {
	scriptFetchDataDB := "fetchDPData_LogReg.py"

	cmd := exec.Command("python3", scriptFetchDataDB, lrParameters.FilePath)
	out, err := cmd.Output()
	if err != nil {println(err.Error())}

	dpData := strings.Split(string(out), "\n")

	//Last entry of dpData is an empty line
	dpData = dpData[:len(dpData)-1]

	tab := make([][]float64, len(dpData))

	firstRow := strings.TrimSuffix(strings.TrimPrefix(dpData[0], "("), ")")
	dimension := len(strings.Split(firstRow, ", "))

	wg := libunlynx.StartParallelize(len(dpData))
	for i, row := range dpData {
		go func(i int, row string) {
			defer wg.Done()
			tab[i] = make([]float64, dimension)
			row = strings.TrimSuffix(strings.TrimPrefix(row, "("), ")")
			values := strings.Split(row, ", ")
			for j, val := range values {
				val64, _ := strconv.ParseFloat(val,64)
				tab[i][j] = val64
			}
		}(i, row)
	}
	libunlynx.EndParallelize(wg)
	return tab, int64(dimension)
}

// createFakeDataForOperation creates fake data to be used
func createFakeDataForOperation(operation libdrynx.Operation, nbrRows, min, max int64) [][]int64 {
	//either use the min and max defined by the query or the default constants
	zero := int64(0)
	if min == zero && max == zero {log.Lvl2("Only generating 0s!")}

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