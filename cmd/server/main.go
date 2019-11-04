package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	kyber_encoding "go.dedis.ch/kyber/v3/util/encoding"
	kyber_key "go.dedis.ch/kyber/v3/util/key"
	onet_app "go.dedis.ch/onet/v3/app"
	onet_log "go.dedis.ch/onet/v3/log"
	onet_network "go.dedis.ch/onet/v3/network"

	"github.com/ldsec/drynx/lib"
	provider "github.com/ldsec/drynx/lib/provider"
	loaders "github.com/ldsec/drynx/lib/provider/loaders"
	drynx_services "github.com/ldsec/drynx/services"

	"github.com/pelletier/go-toml"
	"github.com/urfave/cli"
)

func configModNoArgs(act func(*config)) func(*cli.Context) error {
	return func(c *cli.Context) error {
		if len(c.Args()) > 0 {
			return errors.New("need no argument")
		}

		conf, err := readConfigFrom(os.Stdin)
		if err != nil {
			return err
		}

		act(&conf)

		return conf.writeTo(os.Stdout)
	}
}

func dataProviderNewFileLoader(c *cli.Context) error {
	args := c.Args()
	if len(args) != 1 {
		return errors.New("need a path")
	}
	path := args[0]

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	if conf.DataProvider != nil {
		return errors.New("data-provider already set")
	}
	conf.DataProvider = &configDataProvider{
		FileLoader: &configDataProviderFileLoader{Path: path}}

	return conf.writeTo(os.Stdout)
}

func dataProviderNewRandom(c *cli.Context) error {
	if len(c.Args()) != 0 {
		return errors.New("need no argument")
	}

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	if conf.DataProvider != nil {
		return errors.New("data-provider already set")
	}
	conf.DataProvider = &configDataProvider{Random: &struct{}{}}

	return conf.writeTo(os.Stdout)
}

func gen(c *cli.Context) error {
	args := c.Args()
	if len(args) != 2 {
		return errors.New("need two bind addresses")
	}
	addrNode, addrClient := args.Get(0), args.Get(1)

	address := onet_network.NewAddress(onet_network.PlainTCP, addrNode)
	kp := kyber_key.NewKeyPair(libdrynx.Suite)

	conf := config{
		Address: address,
		URL:     addrClient,
		Key:     *kp,
	}

	return conf.writeTo(os.Stdout)
}

func run(c *cli.Context) error {
	if len(c.Args()) > 0 {
		return errors.New("need no argument")
	}

	conf, err := readConfigFrom(os.Stdin)
	if err != nil {
		return err
	}

	if conf.DataProvider == nil ||
		conf.ComputingNode == nil ||
		conf.VerifyingNode == nil {
		return errors.New("currently, we don't support server specialization, please set all types")
	}

	var loader provider.Loader
	if c := conf.DataProvider.FileLoader; c != nil {
		loader, err = loaders.NewFileLoader(c.Path)
		if err != nil {
			return err
		}
	}

	drynx_services.NewBuilder().
		WithComputingNode().
		WithDataProvider(loader).
		WithVerifyingNode().
		Start()

	pub, err := kyber_encoding.PointToStringHex(libdrynx.Suite, conf.Key.Public)
	if err != nil {
		return err
	}
	priv, _ := kyber_encoding.ScalarToStringHex(libdrynx.Suite, conf.Key.Private)
	if err != nil {
		return err
	}
	serviceKeys := onet_app.GenerateServiceKeyPairs()

	cothorityConf := onet_app.CothorityConfig{
		Address:     conf.Address,
		URL:         conf.URL,
		Suite:       libdrynx.Suite.String(),
		Public:      pub,
		Private:     priv,
		Description: "drynx",
		Services:    serviceKeys,
	}

	configFile, err := ioutil.TempFile("", "onet-stdin")
	if err != nil {
		return err
	}
	defer os.Remove(configFile.Name())

	err = toml.NewEncoder(configFile).Encode(cothorityConf)
	if err != nil {
		return err
	}

	onet_app.RunServer(configFile.Name())

	return nil
}

func main() {
	app := cli.NewApp()
	app.Usage = "configure and start a Drynx node"
	app.Description = fmt.Sprintf(strings.TrimSpace(strings.Replace(`
	configuration uses stdin/stdout.

	if you want to generate a server config, use something like
		%[1]s new {1,2}.drynx.c4dt.org |
			%[1]s data-provider new file-loader $my_data |
			%[1]s computing-node new |
			%[1]s verifying-node new >
			$my_node_config
	then, you can run the given server
		cat $my_node_config | %[1]s run
	`, "\t", "   ", -1)), os.Args[0])

	app.Commands = []cli.Command{{
		Name:   "new",
		Usage:  "generate a server config, start of a server config stream",
		Action: gen,
	}, {
		Name:   "run",
		Usage:  "sink of a server config, run the node as configured",
		Action: run,
	}, {
		Name:  "computing-node",
		Usage: "computing-node configuration",
		Subcommands: []cli.Command{{
			Name:   "new",
			Usage:  "on a server config stream, generate a computing-node config, start a computing-node config stream",
			Action: configModNoArgs(func(conf *config) { conf.ComputingNode = new(struct{}) }),
		}}}, {
		Name:  "data-provider",
		Usage: "data-provider configuration",
		Subcommands: []cli.Command{{
			Name:  "new",
			Usage: "on a server config stream, generate a data-provider config with the given loader, start a data-provider config stream",
			Subcommands: []cli.Command{{
				Name:   "file-loader",
				Action: dataProviderNewFileLoader,
			}, {
				Name:   "random",
				Action: dataProviderNewRandom,
			}},
		}}}, {
		Name:  "verifying-node",
		Usage: "verifying-node configuration",
		Subcommands: []cli.Command{{
			Name:   "new",
			Usage:  "on a server config stream, generate a verifying-node config, start a verifying-node config stream",
			Action: configModNoArgs(func(conf *config) { conf.VerifyingNode = new(struct{}) }),
		}},
	}}

	if err := app.Run(os.Args); err != nil {
		onet_log.Error(err)
	}
}
