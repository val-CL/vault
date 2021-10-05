package dbplugin

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5/proto"

	"google.golang.org/grpc"

	log "github.com/hashicorp/go-hclog"
	plugin "github.com/hashicorp/go-plugin"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/pluginutil"
)

// TODO: storing these plugins should probably live in core. This is currently
//       not thread-safe.
var multiplexedClients map[string]*MultiplexedClient

// DatabasePluginClient embeds a databasePluginRPCClient and wraps its Close
// method to also call Kill() on the plugin.Client.
type DatabasePluginClient struct {
	client *plugin.Client
	sync.Mutex
	multiplexing bool
	id           string
	name         string

	Database
}

// This wraps the Close call and ensures we both close the database connection
// and kill the plugin.
func (dc *DatabasePluginClient) Close() error {
	err := dc.Database.Close()

	// TODO: This leaves child process behind after vault exits
	if !dc.multiplexing {
		dc.client.Kill()
	} else {
		if _, ok := multiplexedClients[dc.name]; !ok {
			return nil
		}

		id := fmt.Sprintf("%s_%s", dc.name, dc.id)
		delete(multiplexedClients[dc.name].connections, id)

		if len(multiplexedClients[dc.name].connections) == 0 {
			dc.client.Kill()
			delete(multiplexedClients, dc.name)
		}
	}

	return err
}

type MultiplexedClient struct {
	sync.Mutex

	clientConn *grpc.ClientConn
	client     *plugin.Client
	gRPCClient gRPCClient

	// TODO: Note, this could be used as a counter only
	connections map[string]Database
}

func (mpc MultiplexedClient) DispensePlugin(id string) (Database, error) {
	mpc.Lock()
	defer mpc.Unlock()

	// Wrap clientConn with our implementation and get rid of middleware
	// and then cast it back and return it

	if mpc.clientConn == nil {
		return nil, errors.New("nil clientConn on MultiplexedClient")
	}

	cc := &databaseClientConn{
		ClientConn: mpc.clientConn,
		id:         id,
	}

	mpc.gRPCClient.client = proto.NewDatabaseClient(cc)

	// TODO: This may not be needed
	mpc.connections[id] = mpc.gRPCClient

	return mpc.gRPCClient, nil

	// db := NewDatabaseMultiplexingMiddleware(mpc.gRPCClient, id)

}

// NewPluginClient returns a databaseRPCClient with a connection to a running
// plugin. The client is wrapped in a DatabasePluginClient object to ensure the
// plugin is killed on call of Close().
func NewPluginClient(ctx context.Context, sys pluginutil.RunnerUtil, pluginRunner *pluginutil.PluginRunner, logger log.Logger, isMetadataMode bool) (Database, error) {
	id, err := base62.Random(10)
	if err != nil {
		return nil, err
	}

	// Case where multiplexed client exists, but we need to create a new entry
	// for the connection
	if mpc, ok := multiplexedClients[pluginRunner.Name]; ok {
		db, err := mpc.DispensePlugin(fmt.Sprintf("%s_%s", pluginRunner.Name, id))
		if err != nil {
			return nil, err
		}

		return &DatabasePluginClient{
			// TODO: we probably want to wrap client instead of providing the root
			//       go-plugin value.
			multiplexing: true,
			client:       mpc.client,
			Database:     db,
			id:           id,
			name:         pluginRunner.Name,
		}, nil
	}

	// pluginSets is the map of plugins we can dispense.
	pluginSets := map[int]plugin.PluginSet{
		5: {
			"database": &GRPCDatabasePlugin{multiplexingSupport: false},
		},
		6: {
			"database": &GRPCDatabasePlugin{multiplexingSupport: true},
		},
	}

	client, err := pluginRunner.RunConfig(ctx,
		pluginutil.Runner(sys),
		pluginutil.PluginSets(pluginSets),
		pluginutil.HandshakeConfig(handshakeConfig),
		pluginutil.Logger(logger),
		pluginutil.MetadataMode(isMetadataMode),
		pluginutil.AutoMTLS(true),
	)
	if err != nil {
		return nil, err
	}

	// Connect via RPC
	rpcClient, err := client.Client()
	if err != nil {
		return nil, err
	}

	// Request the plugin
	raw, err := rpcClient.Dispense("database")
	if err != nil {
		return nil, err
	}

	// We should have a database type now. This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	var db Database
	var multiplexed bool
	switch raw.(type) {
	case gRPCClient:
		gRPCClient := raw.(gRPCClient)
		db = gRPCClient

		// Case where the multiplexed client doesn't exist and we need to create
		// an entry on the map.
		//
		// TODO: this should probably live in Core instead?
		if gRPCClient.MultiplexingSupport() {
			mpc := &MultiplexedClient{
				client:      client,
				gRPCClient:  gRPCClient,
				connections: make(map[string]Database),
			}

			gc, ok := rpcClient.(*plugin.GRPCClient)
			if ok {
				mpc.clientConn = gc.Conn
			}

			if multiplexedClients == nil {
				multiplexedClients = make(map[string]*MultiplexedClient)
			}

			multiplexedClients[pluginRunner.Name] = mpc

			db, err = mpc.DispensePlugin(fmt.Sprintf("%s_%s", pluginRunner.Name, id))
			if err != nil {
				return nil, err
			}
			multiplexed = true
		}
	default:
		return nil, errors.New("unsupported client type")
	}

	// Wrap RPC implementation in DatabasePluginClient
	return &DatabasePluginClient{
		multiplexing: multiplexed,
		client:       client,
		Database:     db,
		id:           id,
		name:         pluginRunner.Name,
	}, nil
}
