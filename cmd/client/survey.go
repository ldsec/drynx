package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli"

	drynx_lib "github.com/ldsec/drynx/lib"
	drynx_services "github.com/ldsec/drynx/services"
	kyber "go.dedis.ch/kyber/v3"
	onet "go.dedis.ch/onet/v3"
	onet_network "go.dedis.ch/onet/v3/network"
)

func surveyNew(c *cli.Context) error {
	args := c.Args()
	if len(args) != 1 {
		return errors.New("need a name")
	}
	name := args.Get(0)

	conf := config{Survey: &configSurvey{Name: &name}}

	return conf.writeTo(os.Stdout)
}

func getRoster(conf configNetwork) (onet.Roster, error) {
	ids := make([]*onet_network.ServerIdentity, len(conf.Nodes))
	for i, e := range conf.Nodes {
		e := e
		ids[i] = &e
	}

	rosterRaw := onet.NewRoster(ids)
	if rosterRaw == nil {
		return onet.Roster{}, errors.New("unable to gen roster based on config")
	}

	return *rosterRaw, nil
}

func surveySetOperation(c *cli.Context) error {
	args := c.Args()
	if len(args) != 1 {
		return errors.New("need an operation")
	}
	operation := args.Get(0)

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	conf.Survey.Operation = &operation

	return conf.writeTo(os.Stdout)
}

func surveyRun(c *cli.Context) error {
	if args := c.Args(); len(args) != 0 {
		return errors.New("no args expected")
	}

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	if conf.Network == nil {
		return errors.New("need some network config")
	}
	roster, err := getRoster(*conf.Network)
	if err != nil {
		return err
	}

	if conf.Network.Client == nil {
		return errors.New("no client defined")
	}
	client := drynx_services.NewDrynxClient(conf.Network.Client, os.Args[0])

	if conf.Survey == nil {
		return errors.New("need some survey config")
	}
	if conf.Survey.Name == nil {
		return errors.New("need a survey name")
	}
	if conf.Survey.Operation == nil {
		return errors.New("need a survey operation")
	}
	sq := client.GenerateSurveyQuery(

		/// network

		&roster, // CN roster
		&roster, // VN roster
		map[string]*[]onet_network.ServerIdentity{ // map CN to DPs
			roster.List[0].String(): &[]onet_network.ServerIdentity{*roster.List[1], *roster.List[2]}},
		map[string]kyber.Point{ // map CN|DP|VN to pub key
			roster.List[0].String(): roster.List[0].Public,
			roster.List[1].String(): roster.List[1].Public,
			roster.List[2].String(): roster.List[2].Public},

		/// gen

		*conf.Survey.Name, // survey id
		drynx_lib.ChooseOperation(
			*conf.Survey.Operation, // operation
			len(roster.List),       // min num of DP to query
			len(roster.List),       // max num of DP to query
			5,                      // dimension for linear regression
			0),                     // "cutting factor", how much to remove of gen data[0:#/n]

		[]*[]int64{}, // range for each output of operation
		nil,          // signature of range validity
		int(0),       // 0 == no proof, 1 == proof, 2 == optimized proof

		false, // obfuscation
		[]float64{
			1.0,  // threshold general
			1.0,  // threshold aggregation
			1.0,  // threshold range
			0.0,  // obfuscation
			1.0}, // threshold key switch
		drynx_lib.QueryDiffP{ // differential privacy
			LapMean: 0.0, LapScale: 0.0, NoiseListSize: 0, Quanta: 0.0, Scale: 0},
		drynx_lib.QueryDPDataGen{ // how to group by
			GroupByValues: []int64{3, 2, 1}, GenerateRows: 10, GenerateDataMin: int64(0), GenerateDataMax: int64(256)},
		0, // cutting factor
	)

	_, aggregations, err := client.SendSurveyQuery(sq)
	if err != nil {
		return err
	}

	result, ok := float64(0), false
	for _, a := range *aggregations {
		if len(a) != 1 {
			return errors.New("line in aggregation larger than one, dunno how to print")
		}
		if ok && result != a[0] {
			return errors.New("not same value found in aggregation, dunno how to print")
		}
		result = a[0]
		ok = true
	}

	fmt.Println(result)

	return nil
}
