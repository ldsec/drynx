package main

import (
	"github.com/dedis/onet/app"
	"gopkg.in/urfave/cli.v1"
	// Empty imports to have the init-functions called which should
	// register the protocol
	_ "github.com/lca1/unlynx/protocols"
	_ "github.com/lca1/unlynx/services/default"
)

func runServer(ctx *cli.Context) error {
	// first check the options
	config := ctx.String("config")
	app.RunServer(config)
	return nil
}
