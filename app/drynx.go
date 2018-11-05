package main

import (
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"os"
)

const (
	// BinaryName is the name of the drynx app
	BinaryName = "drynx"

	// Version of the binary
	Version = "1.00"

	// DefaultGroupFile is the name of the default file to lookup for group
	// definition
	DefaultGroupFile = "group.toml"

	optionConfig      = "config"
	optionConfigShort = "c"

	optionGroupFile      = "file"
	optionGroupFileShort = "f"

	optionOperation = "operation"
	optionOperationShort = "o"

	optionDPs = "d"
	optionDPsShort = "dps"

	optionAttribute = "a"
	optionAttributeShort = "attribute"

	optionQueryMin = "m"
	optionQueryMinShort = "min"

	optionQueryMax = "M"
	optionQueryMaxShort = "max"

	optionProofs = "proofs"

	// query flags
	optionDecryptKey      = "key"
	optionDecryptKeyShort = "k"

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

	encryptFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionGroupFile + ", " + optionGroupFileShort,
			Value: DefaultGroupFile,
			Usage: "Drynx group definition file",
		},
	}

	decryptFlags := []cli.Flag{
		cli.StringFlag{
			Name:  optionDecryptKey + ", " + optionDecryptKeyShort,
			Usage: "Base64-encoded key to decrypt a value",
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
	}

	cliApp.Commands = []cli.Command{
		// BEGIN CLIENT: DATA PROVIDER ----------

		// CLIENT END: DATA PROVIDER ------------

		// BEGIN CLIENT: DATA ENCRYPTION ----------
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "Encrypt an integer with the public key of the collective authority",
			Action:  encryptIntFromApp,
			Flags:   encryptFlags,
		},
		// CLIENT END: DATA ENCRYPTION ------------

		// BEGIN CLIENT: DATA DECRYPTION ----------
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "Decrypt an integer with the provided private key",
			Action:  decryptIntFromApp,
			Flags:   decryptFlags,
		},
		// CLIENT END: DATA DECRYPTION ------------

		// BEGIN CLIENT: QUERIER ----------
		{
			Name:    "run",
			Aliases: []string{"r"},
			Usage:   "Run Drynx service",
			Action:  RunDrynx,
			Flags: querierFlags,
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