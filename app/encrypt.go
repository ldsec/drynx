package main

import (
	"errors"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"gopkg.in/urfave/cli.v1"
	"io"
	"os"
	"strconv"
)

func encryptIntFromApp(c *cli.Context) error {

	// cli arguments
	groupFilePath := c.String("file")

	if c.NArg() != 1 {
		err := errors.New("wrong number of arguments (only 1 allowed, except for the flags)")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	toEncrypt := c.Args().Get(0)
	toEncryptInt, err := strconv.ParseInt(toEncrypt, 10, 64)
	if err != nil {
		log.Error(err)
		return cli.NewExitError(err, 4)
	}

	// generate el with group file
	f, err := os.Open(groupFilePath)
	if err != nil {
		log.Error("Error while opening group file", err)
		return cli.NewExitError(err, 1)
	}
	el, err := app.ReadGroupDescToml(f)
	if err != nil {
		log.Error("Error while reading group file", err)
		return cli.NewExitError(err, 1)
	}
	if len(el.Roster.List) <= 0 {
		log.Error("Empty or invalid group file", err)
		return cli.NewExitError(err, 1)
	}

	// encrypt
	encryptedInt := libunlynx.EncryptInt(el.Roster.Aggregate, toEncryptInt)

	// output in xml format on stdout
	resultString := "<encrypted>" + (*encryptedInt).Serialize() + "</encrypted>\n"
	_, err = io.WriteString(os.Stdout, resultString)
	if err != nil {
		log.Error("Error while writing result.", err)
		return cli.NewExitError(err, 4)
	}

	return nil
}
