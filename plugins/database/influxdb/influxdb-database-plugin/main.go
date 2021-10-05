package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/plugins/database/influxdb"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run instantiates a Influxdb object, and runs the RPC server for the plugin
func Run() error {
	var f func() (dbplugin.Database, error)
	f = influxdb.New()

	dbplugin.ServeMultiplex(f)

	return nil
}
