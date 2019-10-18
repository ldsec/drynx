package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	kyber_encoding "go.dedis.ch/kyber/v3/util/encoding"
	kyber_key "go.dedis.ch/kyber/v3/util/key"
	onet_app "go.dedis.ch/onet/v3/app"
	onet_log "go.dedis.ch/onet/v3/log"
	onet_network "go.dedis.ch/onet/v3/network"

	drynx "github.com/ldsec/drynx/lib"
	_ "github.com/ldsec/drynx/protocols"
	_ "github.com/ldsec/drynx/services"

	"github.com/pelletier/go-toml"
	"github.com/urfave/cli"
)

func toTmpFile(reader io.Reader) (os.File, error) {
	file, err := ioutil.TempFile("", "onet-stdin")
	if err != nil {
		return os.File{}, err
	}

	content, err := ioutil.ReadAll(reader)
	if err != nil {
		return os.File{}, err
	}
	if _, err = file.Write(content); err != nil {
		return os.File{}, err
	}

	return *file, nil
}

func gen(c *cli.Context) error {
	args := c.Args()
	if len(args) != 2 {
		return errors.New("need two bind addresses")
	}
	addrNode, addrClient := args.Get(0), args.Get(1)

	onet_log.OutputToBuf() // reduce garbage to stdout

	serverBinding := onet_network.NewAddress(onet_network.PlainTCP, addrNode)
	kp := kyber_key.NewKeyPair(drynx.Suite)

	pub, err := kyber_encoding.PointToStringHex(drynx.Suite, kp.Public)
	if err != nil {
		return err
	}
	priv, _ := kyber_encoding.ScalarToStringHex(drynx.Suite, kp.Private)
	if err != nil {
		return err
	}

	serviceKeys := onet_app.GenerateServiceKeyPairs()

	conf := onet_app.CothorityConfig{
		Suite:         drynx.Suite.String(),
		Public:        pub,
		Private:       priv,
		Address:       serverBinding,
		ListenAddress: addrNode,
		URL:           "https://" + addrClient,
		Description:   "drynx",
		Services:      serviceKeys,
	}

	err = toml.NewEncoder(os.Stdout).Encode(conf)

	return err
}

func run(c *cli.Context) error {
	args := c.Args()
	if len(c.Args()) > 0 {
		return errors.New("need no argument")
	}

	config := args.First()
	if !args.Present() {
		configFile, err := toTmpFile(os.Stdin)
		if err != nil {
			return err
		}
		defer os.Remove(configFile.Name())

		config = configFile.Name()
	}

	onet_app.RunServer(config)

	return nil
}

func main() {
	app := cli.NewApp()
	app.Usage = "configure and start a Drynx node"
	app.Description = fmt.Sprintf(strings.TrimSpace(strings.Replace(`
	configuration uses stdin/stdout.

	if you want to generate a server config, use something like
		%[1]s gen > $my_server_config
	then, you can run it
		cat $my_server_config | %[1]s run
	`, "\t", "   ", -1)), os.Args[0])

	app.Commands = []cli.Command{
		{
			Name:      "gen",
			ArgsUsage: "host:node-port host:client-port",
			Usage:     "generate a server config, start a server config stream",
			Action:    gen,
		}, {
			Name:   "run",
			Usage:  "sink of a server config, run the node",
			Action: run,
		},
	}

	if err := app.Run(os.Args); err != nil {
		onet_log.Error(err)
	}
}
