package main

import (
	"fmt"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/onet"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/drynx/lib"
	"github.com/lca1/drynx/services"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// BEGIN SERVER: DP or COMPUTING NODE ----------

// NonInteractiveSetup is used to setup the cothority node for unlynx in a non-interactive way (and without error checks)
func NonInteractiveSetup(c *cli.Context) error {

	// cli arguments
	serverBindingStr := c.String("serverBinding")
	description := c.String("description")
	privateTomlPath := c.String("privateTomlPath")
	publicTomlPath := c.String("publicTomlPath")

	if serverBindingStr == "" || description == "" || privateTomlPath == "" || publicTomlPath == "" {
		err := errors.New("arguments not OK")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	kp := key.NewKeyPair(libunlynx.SuiTe)

	privStr, _ := encoding.ScalarToStringHex(libunlynx.SuiTe, kp.Private)
	pubStr, _ := encoding.PointToStringHex(libunlynx.SuiTe, kp.Public)
	public, _ := encoding.StringHexToPoint(libunlynx.SuiTe, pubStr)

	//serverBinding := network.NewTLSAddress(serverBindingStr)
	serverBinding := network.NewTCPAddress(serverBindingStr)
	conf := &app.CothorityConfig{
		Suite:       libunlynx.SuiTe.String(),
		Public:      pubStr,
		Private:     privStr,
		Address:     serverBinding,
		Description: description,
	}

	server := app.NewServerToml(libunlynx.SuiTe, public, serverBinding, conf.Description)
	group := app.NewGroupToml(server)

	err := conf.Save(privateTomlPath)
	if err != nil {
		log.Fatal(err)
	}

	group.Save(publicTomlPath)
	return nil
}

// BEGIN CLIENT: QUERIER ----------
// how to repartition the DPs: each server as a list of data providers
func repartitionDPs(elServers *onet.Roster, elDPs *onet.Roster, dpRepartition []int64) map[string]*[]network.ServerIdentity {
	if len(dpRepartition) > len(elServers.List) {
		log.Fatal("Cannot assign the DPs to", len(dpRepartition), "servers (", len(elServers.List), ")")
	}

	dpToServers := make(map[string]*[]network.ServerIdentity, 0)
	count := 0
	for i, v := range elServers.List {
		index := v.String()
		value := make([]network.ServerIdentity, dpRepartition[i])
		dpToServers[index] = &value
		for j := range *dpToServers[index] {
			val := elDPs.List[count]
			count = count + 1
			(*dpToServers[index])[j] = *val
		}
	}
	return dpToServers
}

// RunDrynx runs a query
func RunDrynx(c *cli.Context) error {
	scriptPopulateDB := "/Users/jstephan/go/src/github.com/lca1/drynx/app/db.py"

	elServers, err := openGroupToml("test/groupServers.toml")
	if err != nil {log.Fatal("Could not read groupServers.toml")}
	elDPs, err := openGroupToml("test/groupDPs.toml")
	if err != nil {log.Fatal("Could not read groupDPs.toml")}

	proofs := int64(0) // 0 is not proof, 1 is proofs, 2 is optimized proofs
	rangeProofs := false
	obfuscation := false

	diffPri := false
	diffPriOpti := false
	nbrRows := int64(1)
	//repartition: server1: 1 DP, server2: 1 DP, server3: 1 DP
	repartition := []int64{1, 1, 1}

	//simulation
	cuttingFactor := int64(0)

	//Get the query operation to be executed
	operationQuery := c.String("operation")

	var operationList []string
	if operationQuery == "all" {
		operationList = []string{"sum", "mean", "variance", "cosim", "frequencyCount", "bool_AND", "bool_OR", "min", "max", "lin_reg", "union", "inter"}
	} else {operationList = []string{operationQuery}}

	thresholdEntityProofsVerif := []float64{1.0, 1.0, 1.0, 1.0} // 1: threshold general, 2: threshold range, 3: obfuscation, 4: threshold key switch

	if proofs == 1 {
		if obfuscation {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 1.0, 1.0}
		} else {
			thresholdEntityProofsVerif = []float64{1.0, 1.0, 0.0, 1.0}
		}
	} else {
		thresholdEntityProofsVerif = []float64{0.0, 0.0, 0.0, 0.0}
	}
	dpToServers := repartitionDPs(elServers, elDPs, repartition)

	// Create a client (querier) for the service)
	client := services.NewDrynxClient(elServers.List[0], "test-Drynx")

	for _, op := range operationList {
		queryAnswer := ""

		// data providers data generation
		minGenerateData := int64(3)
		maxGenerateData := int64(4)
		dimensions := int64(5)
		operation := libdrynx.ChooseOperation(op, minGenerateData, maxGenerateData, dimensions, cuttingFactor)

		// define the number of groups for groupBy (1 per default)
		dpData := libdrynx.QueryDPDataGen{GroupByValues: []int64{1}, GenerateRows: nbrRows, GenerateDataMin: int64(minGenerateData), GenerateDataMax: int64(maxGenerateData)}

		// define the ranges for the input validation (1 range per data provider output)
		var u, l int64
		if proofs == 0 {
			rangeProofs = false
		} else {
			if op == "bool_AND" || op == "bool_OR" || op == "min" || op == "max" || op == "union" || op == "inter" {
				if obfuscation {
					rangeProofs = true
					u = int64(2)
					l = int64(1)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}

			} else {
				obfuscation = false

				if rangeProofs {
					u = int64(16)
					l = int64(16)
				} else {
					rangeProofs = true
					u = int64(0)
					l = int64(0)
				}
			}
		}

		ranges := make([]*[]int64, operation.NbrOutput)
		if rangeProofs {
			for i := range ranges {
				ranges[i] = &[]int64{u, l}
			}
		} else {ranges = nil}

		// choose if differential privacy or not, no diffP by default
		// choosing the limit is done by drawing the curve (e.g. wolframalpha)
		diffP := libdrynx.QueryDiffP{}
		if diffPri {
			diffP = libdrynx.QueryDiffP{LapMean: 0, LapScale: 15.0, NoiseListSize: 1000, Limit: 65, Scale: 1, Optimized: diffPriOpti}
		} else {
			diffP = libdrynx.QueryDiffP{LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0, Optimized: diffPriOpti}
		}

		// DPs signatures for Input Range Validation
		ps := make([]*[]libdrynx.PublishSignatureBytes, len(elServers.List))

		if ranges != nil && u != int64(0) && l != int64(0) {
			for i := range elServers.List {
				temp := make([]libdrynx.PublishSignatureBytes, len(ranges))
				for j := 0; j < len(ranges); j++ {
					if cuttingFactor != 0 {
						temp[j] = libdrynx.InitRangeProofSignatureDeterministic((*ranges[j])[0])
					} else {
						temp[j] = libdrynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
					}
				}
				ps[i] = &temp
			}
		} else {ps = nil}

		// QUERY RECAP
		log.LLvl1("\n")
		log.LLvl1("#----- QUERY -----#")
		log.LLvl1("Service Drynx Test with suite:", libunlynx.SuiTe.String(), "and query:")
		log.LLvl1("SELECT ", operation, " ... FROM DP1, ..., DP", len(elDPs.List), " WHERE ... GROUP BY ", dpData.GroupByValues)
		if ranges == nil || (u == int64(0) && l == int64(0)) {
			log.LLvl1("No input range validation")
		} else {
			log.LLvl1("with input range validation (", len(ps), " x ", len(*ps[0]), ")")
		}
		if libdrynx.AddDiffP(diffP) {
			log.LLvl1(" with differential privacy with epsilon=", diffP.LapMean, " and delta=", diffP.LapScale)
		} else {
			log.LLvl1(" no differential privacy")
		}
		log.LLvl1("#-----------------#\n")
		//-----------

		idToPublic := make(map[string]kyber.Point)
		for _, v := range elServers.List {idToPublic[v.String()] = v.Public}
		for _, v := range elDPs.List {idToPublic[v.String()] = v.Public}

		// query generation
		surveyID := "query-" + op
		log.LLvl1(dpToServers)

		//DPs over which the query is executed
		dpsUsed := []*network.ServerIdentity{elDPs.List[0], elDPs.List[1]}

		sq := client.GenerateSurveyQuery(elServers, nil, dpToServers, idToPublic, surveyID, operation,
			ranges, ps, proofs, obfuscation, thresholdEntityProofsVerif, diffP, dpData, cuttingFactor, dpsUsed)
		if !libdrynx.CheckParameters(sq, diffPri) {log.Fatal("Oups!")}

		// send query and receive results
		grp, aggr, _ := client.SendSurveyQuery(sq)

		// Result printing
		if len(*grp) != 0 && len(*grp) != len(*aggr) {
			log.Fatal("Results format problem")
		} else {
			for i, v := range *aggr {
				//log.LLvl1("Value " + string(i) + " is: " + string(v[0]))
				log.LLvl1((*grp)[i], ": ", v)
				for j := range v {queryAnswer += strconv.FormatFloat(v[j], 'f', 6, 64) + ", "}
			}
			queryAnswer = strings.TrimSuffix(queryAnswer, ", ")
		}
		log.LLvl1("Operation " + op + " is done successfully.")

		//Store query answer in local database
		log.LLvl1("Update local database.")
		cmd := exec.Command("python", scriptPopulateDB, queryAnswer,
			strconv.Itoa(int(time.Now().Unix())), operation.NameOp, "BPM")
		out, err := cmd.Output()
		if err != nil {println(err.Error())}
		fmt.Println(string(out))
	}

	log.LLvl1("All done.")
	return nil
}

func openGroupToml(tomlFileName string) (*onet.Roster, error) {
	f, err := os.Open(tomlFileName)
	if err != nil {
		return nil, err
	}
	el, err := app.ReadGroupDescToml(f)
	if err != nil {
		return nil, err
	}

	if len(el.Roster.List) <= 0 {
		return nil, errors.New("Empty or invalid drynx group file:" + tomlFileName)
	}

	return el.Roster, nil
}

// CLIENT END: QUERIER ----------