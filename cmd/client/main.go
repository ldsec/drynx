package main

import (
	"fmt"
	"os"
	"strings"

	onet_log "go.dedis.ch/onet/v3/log"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Usage = "communicate with a Drynx network"
	app.Description = fmt.Sprintf(strings.TrimSpace(strings.Replace(`
	configuration uses stdin/stdout.

	if you want to generate a network config, use something like
		%[1]s network new |
			%[1]s network add-node 1.drynx.c4dt.org 1234abc |
			%[1]s network set-client 2.drynx.c4dt.org 5678def >
			$my_network_config
	if you want to generate a survey config, use something like
		%[1]s survey new my-survey |
			%[1]s survey set-sources my-column |
			%[1]s survey set-operation mean >
			$my_survey_config
	then, you can launch a given survey on a given network
		cat $my_network_config $my_survey_config |
			%[1]s survey new run
	`, "\t", "   ", -1)), os.Args[0])

	app.Commands = []cli.Command{{
		Name:  "network",
		Usage: "network configuration",
		Subcommands: []cli.Command{{
			Name:   "new",
			Usage:  "generate an empty network config, start a network config stream",
			Action: networkNew,
		}, {
			Name:      "add-node",
			ArgsUsage: "host:node-port node-public-key-as-hex",
			Usage:     "on a network config stream, add a node with a public key",
			Action:    networkAddNode,
		}, {
			Name:      "set-client",
			ArgsUsage: "host:client-port",
			Usage:     "on a network config stream, set the client to send the survey query to",
			Action:    networkSetClient,
		}}}, {
		Name:  "survey",
		Usage: "network operations",
		Subcommands: []cli.Command{{
			Name:      "new",
			ArgsUsage: "name",
			Usage:     "generate a survey config with the given name, start a survey config stream",
			Action:    surveyNew,
		}, {
			Name:      "set-sources",
			ArgsUsage: "column-name...",
			Usage:     "on a survey config stream, set the sources columns names",
			Action:    surveySetSources,
		}, {
			Name:      "set-operation",
			ArgsUsage: "operation",
			// TODO use op generated list
			Usage:  "on a survey config stream, set the operation to use, try sum/mean/count/…",
			Action: surveySetOperation,
		}, {
			Name:      "run",
			ArgsUsage: "client-to-connect public-of-client",
			Usage:     "sink of a survey and network stream, run the survey on the network",
			Action:    surveyRun,
		}}}}

	if err := app.Run(os.Args); err != nil {
		onet_log.Error(err)
	}
}
