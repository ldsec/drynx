package main

import (
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"os"
)

const (
	// query flags

	// BinaryName is the name of the drynx app
	BinaryName = "drynx"

	// Version of the binary
	Version = "1.00"

	optionConfig      = "config"
	optionConfigShort = "c"

	optionOperation      = "operation"
	optionOperationShort = "o"

	optionDPs      = "dps"
	optionDPsShort = "d"

	optionAttribute      = "attributes"
	optionAttributeShort = "a"

	optionQueryMin      = "min"
	optionQueryMinShort = "m"

	optionQueryMax      = "max"
	optionQueryMaxShort = "M"

	//for proofs verification
	optionProofs = "proofs"
	optionProofsShort = "p"

	//Total Number of trials to train and evaluate the logistic regression model
	optionNmbrTrials = "trials"
	optionNmbrTrialsShort = "t"

	// setup options
	optionServerBinding      = "serverBinding"
	optionServerBindingShort = "sb"

	optionDescription      = "description"
	optionDescriptionShort = "desc"

	optionPrivateTomlPath      = "privateTomlPath"
	optionPrivateTomlPathShort = "priv"

	optionPublicTomlPath      = "publicTomlPath"
	optionPublicTomlPathShort = "pub"
)

func main() {
	cliApp := cli.NewApp()
	cliApp.Name = BinaryName
	cliApp.Usage = "Query information securely and privately"
	cliApp.Version = Version

	binaryFlags := []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}

	nonInteractiveSetupFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionServerBinding + ", " + optionServerBindingShort,
			Usage: "Server binding address in the form of address:port",
		},
		cli.StringFlag{
			Name:  optionDescription + ", " + optionDescriptionShort,
			Usage: "Description of the node for the toml files",
		},
		cli.StringFlag{
			Name:  optionPrivateTomlPath + ", " + optionPrivateTomlPathShort,
			Usage: "Private toml file path",
		},
		cli.StringFlag{
			Name:  optionPublicTomlPath + ", " + optionPublicTomlPathShort,
			Usage: "Public toml file path",
		},
	}

	serverFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionConfig + ", " + optionConfigShort,
			Usage: "Configuration file of the server",
		},
	}

	querierFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionOperation + ", " + optionOperationShort,
			Usage: "Operation to be run by querier",
		},

		cli.StringFlag{
			Name:  optionDPs + ", " + optionDPsShort,
			Usage: "DPs over which query is run",
		},

		cli.StringFlag{
			Name:  optionAttribute + ", " + optionAttributeShort,
			Usage: "Attribute over which query is run",
		},

		cli.StringFlag{
			Name:  optionQueryMin + ", " + optionQueryMinShort,
			Usage: "Minimum of data to be examined while executing query",
		},

		cli.StringFlag{
			Name:  optionQueryMax + ", " + optionQueryMaxShort,
			Usage: "Maximum of data to be examined while executing query",
		},

		cli.Int64Flag{
			Name:  optionProofs + ", " + optionProofsShort,
			Usage: "Is Proofs Verification enabled?",
		},

		cli.Int64Flag{
			Name:  optionNmbrTrials + ", " + optionNmbrTrialsShort,
			Usage: "Number of Trials to train (and evaluate) logistic regression model",
		},
	}

	cliApp.Commands = []cli.Command{
		// BEGIN CLIENT: QUERIER ----------
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run Drynx service",
			Action:  RunDrynx,
			Flags:   querierFlags,
		},
		// CLIENT END: QUERIER ----------

		// BEGIN SERVER --------
		{
			Name:  "server",
			Usage: "Start Drynx server",
			Action: func(c *cli.Context) error {
				runServer(c)
				return nil
			},
			Flags: serverFlags,
			Subcommands: []cli.Command{
				{
					Name:    "setup",
					Aliases: []string{"s"},
					Usage:   "Setup server configuration (interactive)",
					Action: func(c *cli.Context) error {
						if c.String(optionConfig) != "" {
							log.Fatal("[-] Configuration file option cannot be used for the 'setup' command")
						}
						if c.GlobalIsSet("debug") {
							log.Fatal("[-] Debug option cannot be used for the 'setup' command")
						}
						app.InteractiveConfig(libunlynx.SuiTe, BinaryName)
						return nil
					},
				},
				{
					Name:    "setupNonInteractive",
					Aliases: []string{"sni"},
					Usage:   "Setup server configuration (non-interactive)",
					Action:  NonInteractiveSetup,
					Flags:   nonInteractiveSetupFlags,
				},
			},
		},
		// SERVER END ----------
	}

	cliApp.Flags = binaryFlags
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.GlobalInt("debug"))
		return nil
	}
	err := cliApp.Run(os.Args)
	log.ErrFatal(err)
}