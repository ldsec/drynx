package main

import (
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
	"gopkg.in/urfave/cli.v1"
	"os"
)

func runServer(ctx *cli.Context) {
	// first check the options
	configFilename := ctx.String("config")
	dbPath := ctx.String("database")
	tableName := ctx.String("table")

	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		log.Fatalf("[-] Configuration file does not exist. %s", configFilename)
	}
	// Let's read the config
	_, server, err := app.ParseCothority(configFilename)
	if err != nil {log.Fatal("Couldn't parse config:", err)}
	server.ServerIdentity.Description= dbPath + "," + tableName
	server.Start()
	return
}