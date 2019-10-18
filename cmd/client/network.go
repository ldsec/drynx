package main

import (
	"errors"
	"os"

	kyber_util_encoding "go.dedis.ch/kyber/v3/util/encoding"
	onet_network "go.dedis.ch/onet/v3/network"

	drynx_lib "github.com/ldsec/drynx/lib"

	"github.com/urfave/cli"
)

func networkNew(c *cli.Context) error {
	if len(c.Args()) > 0 {
		return errors.New("no args expected")
	}

	conf := config{Network: &configNetwork{}}

	return conf.writeTo(os.Stdout)
}

func networkAddNode(c *cli.Context) error {
	args := c.Args()
	if len(args) != 2 {
		return errors.New("need a host and its public key")
	}
	host, publicHex := args.Get(0), args.Get(1)

	public, err := kyber_util_encoding.StringHexToPoint(drynx_lib.Suite, publicHex)
	if err != nil {
		return err
	}
	addr := onet_network.NewTCPAddress(host)
	id := *onet_network.NewServerIdentity(public, addr)

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	conf.Network.Nodes = append(conf.Network.Nodes, id)

	return conf.writeTo(os.Stdout)
}

func networkSetClient(c *cli.Context) error {
	args := c.Args()
	if len(args) != 1 {
		return errors.New("need a client")
	}
	client := args.Get(0)

	id := onet_network.ServerIdentity{URL: "http://" + client}

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	conf.Network.Client = &id

	return conf.writeTo(os.Stdout)
}
