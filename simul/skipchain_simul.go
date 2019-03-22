package main

/*import (
	"errors"

	"github.com/BurntSushi/toml"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/common"
	"github.com/lca1/unlynx/services/skipChain"
)

//Defines the simulation for the service-skipchain to be run with cothority/simul.
func init() {
	onet.SimulationRegister("ServiceSkipchain", NewSimulationSkipchain)
}

// NewSimulationSkipchain constructs a full  service simulation.
func NewSimulationSkipchain(config string) (onet.Simulation, error) {
	es := &SimulationSkipchain{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// SimulationUnLynx the state of a simulation.
type SimulationSkipchain struct {
	onet.SimulationBFTree

	// Settings
	// Topology
	NbrServersCA      int
	DpRepartition     []int64
	NbrVerifyingNodes int
	DPByServer        int
	StaticDpNumber    int

	// Query
	Threshold     float64
	RangeByDP     int
	Ranges        []int64
	ProofByServer []int64
	//Specific Proofs
	KeySwitchingProofThreshold float64
	RangeProofThreshold        float64
}

func (sim *SimulationSkipchain) Setup(dir string, hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}

	sim.CreateRoster(sc, hosts, 2000)
	err := sim.CreateTree(sc)

	if err != nil {
		return nil, err
	}

	log.Lvl1("Setup done")

	return sc, nil
}

func (sim *SimulationSkipchain) Run(config *onet.SimulationConfig) error {
	// has to be set here because cannot be in toml file
	diffP := common.QueryDiffP{Scale: 1.0, Quanta: 1.0, NoiseListSize: 1, Limit: 1.0, LapMean: 1.0, LapScale: 1.0}
	// operation
	operation := common.Operation{NbrInput: 1, NbrOutput: 1}

	ranges := make([]*[]int64, sim.RangeByDP)
	// create the ranges for input validation if needed and if pairing curve is used
	if !libunlynx.CurvePairingTest() {
		//for i := 0; i < len(sim.Ranges); i = i + 2{
		for i := 0; i < (2 * sim.RangeByDP); i = i + 2 {
			u := int64(sim.Ranges[0])
			l := int64(sim.Ranges[1])
			ranges[i/2] = &[]int64{u, l}
		}
	} else {
		ranges = nil
	}

	// signatures for Input Validation
	ps := make([]*[]libunlynx.PublishSignatureBytes, sim.NbrServersCA)
	if !(ranges == nil) {
		for i := 0; i < sim.NbrServersCA; i++ {
			temp := make([]libunlynx.PublishSignatureBytes, len(ranges))
			for j := 0; j < len(ranges); j++ {
				temp[j] = libunlynx.InitRangeProofSignature((*ranges[j])[0]) // u is the first elem
			}
			ps[i] = &temp
		}
	} else {
		ps = nil
	}

	//define servers and data providers in the set of nodes + adapt the aggregate key (CA public key)
	elTotal := (*config.Tree).Roster
	log.Lvl1("NUMBER HOST", len(elTotal.List))
	elVNs := elTotal.List[:sim.NbrVerifyingNodes]
	elServers := elTotal.List[sim.NbrVerifyingNodes : sim.NbrVerifyingNodes+sim.NbrServersCA]
	elDps := elTotal.List[sim.NbrVerifyingNodes+sim.NbrServersCA:]
	if len(elVNs)+len(elServers)+len(elDps) != sim.Hosts {
		log.ErrFatal(errors.New("Number host not the same as expected"), "Error setting number of client/server")
	}
	log.Lvl1("NUMBER SERV ", sim.NbrServersCA)
	log.Lvl1("NUMBER DP", len(elDps))
	log.Lvl1("NUMBER VN", len(elVNs))
	idToPublic := make(map[string]kyber.Point)

	serverClient := make([]*skipChain.API, len(elServers))
	dpsClient := make([]*skipChain.API, len(elDps))

	for i, v := range elServers {
		priv, pub := libunlynx.GenKey()
		serverClient[i] = skipChain.NewSkipChainClient(v.Address.String())
		serverClient[i].Private = priv
		idToPublic[v.Address.String()] = pub
	}

	for i, v := range elDps {
		priv, pub := libunlynx.GenKey()
		dpsClient[i] = skipChain.NewSkipChainClient(v.Address.String())
		dpsClient[i].Private = priv
		idToPublic[v.Address.String()] = pub
	}

	dpToServers := make(map[string]*[]network.ServerIdentity, 0)
	count := 0

	if sim.StaticDpNumber != 0 {
		remainingDP := sim.StaticDpNumber
		DPByServ := sim.StaticDpNumber / sim.NbrServersCA
		if DPByServ == 0 {
			DPByServ = 1
		}
		for i, v := range elServers {
			index := v.String()
			value := make([]network.ServerIdentity, 0)
			if remainingDP > 0 {
				if i == len(elServers)-1 {
					value = make([]network.ServerIdentity, remainingDP)
					remainingDP = 0
				} else if remainingDP-DPByServ < 0 {
					value = make([]network.ServerIdentity, remainingDP)
					remainingDP = 0
				} else {
					value = make([]network.ServerIdentity, DPByServ)
					remainingDP -= DPByServ
				}
			}
			dpToServers[index] = &value
			for j := range *dpToServers[index] {
				val := elDps[count]
				count = count + 1
				(*dpToServers[index])[j] = *val
			}
		}
	} else {
		for _, v := range elServers {
			index := v.String()
			value := make([]network.ServerIdentity, sim.DPByServer)
			dpToServers[index] = &value
			for j := range *dpToServers[index] {
				val := elDps[count]
				count = count + 1
				(*dpToServers[index])[j] = *val
			}
		}
	}
	for round := 0; round < sim.Rounds; round++ {
		log.Lvl1("Start round ", round)
		rosterServer := onet.NewRoster(elVNs)

		query := common.SurveyQuery{Query: common.Query{
			Operation: operation,
			Ranges:    ranges,
			DiffP:     diffP,
			Proofs:    1, //To process the proofs
		}, RosterServers: *rosterServer, SurveyID: "test", ClientPubKey: nil, ServerToDP: dpToServers,
			IDtoPublic: idToPublic, Threshold: sim.Threshold, KeySwitchingProofThreshold: sim.KeySwitchingProofThreshold,
			RangeProofThreshold: sim.RangeProofThreshold}

		Allproofs := skipChain.CreateRandomGoodTestData(rosterServer, idToPublic[elServers[0].Address.String()], (*ranges[0])[0], (*ranges[0])[1])

		randomIndex := 2
		serverClient[randomIndex].SendQuery(rosterServer, &query)
		blockGenesis := &skipchain.SkipBlock{}

		for _, v := range dpsClient {
			rangeList := &libunlynx.RangeProofList{}
			rangeList.Data = make([]libunlynx.RangeProof, 0)
			for k := 0; k < sim.RangeByDP; k++ {
				rangeList.Data = append(rangeList.Data, Allproofs.ProofsRange[k].Data[0])
			}
			v.SendRange("test", rosterServer, rangeList, string(0), nil)
		}
		for _, v := range serverClient {
			for k := 0; k < int(sim.ProofByServer[0]); k++ {
				v.SendAggregation("test", rosterServer, Allproofs.ProofsAggregation[0], string(k), nil)
			}
			for k := 0; k < int(sim.ProofByServer[1]); k++ {
				v.SendShuffle("test", rosterServer, Allproofs.ProofShuffle[0], string(k), nil, "")
			}
			for k := 0; k < int(sim.ProofByServer[2]); k++ {
				blockGenesis, _ = v.SendKeySwitch("test", rosterServer, Allproofs.ProofsKeySwitch[0], string(k), nil, "")
			}
		}

		block2, _ := serverClient[0].GetLatestBlock(rosterServer, blockGenesis)

		if blockGenesis == nil && !blockGenesis.Equal(block2) {
			log.Fatal("Something went wrong")
		}

		query2 := common.SurveyQuery{Query: common.Query{
			Operation: operation,
			Ranges:    ranges,
			DiffP:     diffP,
			Proofs:    1, //To process the proofs
		}, RosterServers: *rosterServer, SurveyID: "test2", ClientPubKey: nil, ServerToDP: dpToServers,
			IDtoPublic: idToPublic, Threshold: sim.Threshold, KeySwitchingProofThreshold: sim.KeySwitchingProofThreshold,
			RangeProofThreshold: sim.RangeProofThreshold}

		serverClient[randomIndex].SendQuery(rosterServer, &query2)
		blockFollowing := &skipchain.SkipBlock{}

		for _, v := range dpsClient {

			rangeList := &libunlynx.RangeProofList{}
			for k := 0; k < sim.RangeByDP; k++ {
				rangeList.Data = append(rangeList.Data, Allproofs.ProofsRange[0].Data[0])
			}
			v.SendRange("test2", rosterServer, rangeList, string(0), nil)
		}
		for _, v := range serverClient {
			for k := 0; k < int(sim.ProofByServer[0]); k++ {
				v.SendAggregation("test2", rosterServer, Allproofs.ProofsAggregation[0], string(k), nil)
			}
			for k := 0; k < int(sim.ProofByServer[1]); k++ {
				v.SendShuffle("test2", rosterServer, Allproofs.ProofShuffle[0], string(k), nil, "")
			}
			for k := 0; k < int(sim.ProofByServer[2]); k++ {
				blockFollowing, _ = v.SendKeySwitch("test2", rosterServer, Allproofs.ProofsKeySwitch[0], string(k), blockGenesis, "")
			}
		}

		if blockFollowing == nil {
			log.Fatal("Error in new block")
		}

		serverClient[0].GetProofsFrom("test2", elVNs[0])
		serverClient[0].GetLatestBlock(rosterServer, blockFollowing)
	}
	return nil

}*/
