package main

import (
	"gopkg.in/urfave/cli.v1"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/onet/app"
	"strconv"
	"io"
	"os"
	"errors"
	"github.com/dedis/kyber/util/encoding"
	"github.com/dedis/onet/network"
	"github.com/dedis/kyber/util/key"
)

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

	serverBinding := network.NewTLSAddress(serverBindingStr)
	conf := &app.CothorityConfig{
		Public:      pubStr,
		Private:     privStr,
		Address:     serverBinding,
		Description: description,
	}

	server := app.NewServerToml(libunlynx.SuiTe, public, serverBinding, conf.Description)
	group := app.NewGroupToml(server)

	err := conf.Save(privateTomlPath)
	log.LLvl1(err)
	group.Save(publicTomlPath)

	return nil
}

func decryptIntFromApp(c *cli.Context) error {

	// cli arguments
	secKeySerialized := c.String("key")
	secKey, err := libunlynx.DeserializeScalar(secKeySerialized)
	if err != nil {
		log.Error(err)
		return cli.NewExitError(err, 4)
	}

	if c.NArg() != 1 {
		err := errors.New("wrong number of arguments (only 1 allowed, except for the flags)")
		log.Error(err)
		return cli.NewExitError(err, 3)
	}

	// value to decrypt
	toDecryptSerialized := c.Args().Get(0)
	toDecrypt := libunlynx.NewCipherTextFromBase64(toDecryptSerialized)

	// decryption
	decVal := libunlynx.DecryptInt(secKey, *toDecrypt)

	// output in xml format on stdout
	resultString := "<decrypted>" + strconv.FormatInt(decVal, 10) + "</decrypted>\n"
	_, err = io.WriteString(os.Stdout, resultString)
	if err != nil {
		log.Error("Error while writing result.", err)
		return cli.NewExitError(err, 4)
	}

	return nil
}