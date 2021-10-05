package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/plugins/database/cassandra"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run instantiates a Cassandra object, and runs the RPC server for the plugin
func Run() error {
	dbplugin.ServeMultiplex(cassandra.New)

	return nil
}
