package main

import (
	"io"

	kyber_encoding "go.dedis.ch/kyber/v3/util/encoding"
	onet_network "go.dedis.ch/onet/v3/network"

	drynx_lib "github.com/ldsec/drynx/lib"

	"github.com/pelletier/go-toml"
)

type configNetwork struct {
	Client *onet_network.ServerIdentity
	Nodes  []onet_network.ServerIdentity
}
type configSurvey struct {
	Name      *string
	Operation *string
}
type config struct {
	Network *configNetwork
	Survey  *configSurvey
}

type serverIdentityStr struct {
	Address   onet_network.Address
	PublicKey string
}
type clientIdentityStr struct {
	URL string
}
type configNetworkStr struct {
	Client *clientIdentityStr
	Nodes  []serverIdentityStr
}
type configStr struct {
	Network *configNetworkStr
	Survey  *configSurvey
}

func serverIdentityToUnsafe(id onet_network.ServerIdentity) (serverIdentityStr, error) {
	point, err := kyber_encoding.PointToStringHex(drynx_lib.Suite, id.Public)
	if err != nil {
		return serverIdentityStr{}, err
	}
	return serverIdentityStr{id.Address, point}, nil
}

func clientIdentityToUnsafe(id onet_network.ServerIdentity) (clientIdentityStr, error) {
	return clientIdentityStr{id.URL}, nil
}

func (conf configNetwork) toUnsafe() (configNetworkStr, error) {
	var client *clientIdentityStr
	if conf.Client != nil {
		clientStruct, err := clientIdentityToUnsafe(*conf.Client)
		if err != nil {
			return configNetworkStr{}, err
		}
		client = &clientStruct
	}

	nodes := make([]serverIdentityStr, len(conf.Nodes))
	for i, n := range conf.Nodes {
		var err error
		if nodes[i], err = serverIdentityToUnsafe(n); err != nil {
			return configNetworkStr{}, err
		}
	}

	return configNetworkStr{client, nodes}, nil
}

func (conf configNetworkStr) toSafe() (configNetwork, error) {
	var client *onet_network.ServerIdentity
	if conf.Client != nil {
		client = &onet_network.ServerIdentity{URL: conf.Client.URL}
	}

	nodes := make([]onet_network.ServerIdentity, len(conf.Nodes))
	for i, n := range conf.Nodes {
		point, err := kyber_encoding.StringHexToPoint(drynx_lib.Suite, n.PublicKey)
		if err != nil {
			return configNetwork{}, err
		}
		nodes[i] = *onet_network.NewServerIdentity(point, n.Address)
	}

	return configNetwork{client, nodes}, nil
}

func readConfigFrom(r io.Reader) (config, error) {
	var conf configStr
	err := toml.NewDecoder(r).Decode(&conf)
	if err != nil {
		return config{}, err
	}

	var network *configNetwork
	if conf.Network != nil {
		networkStruct, err := conf.Network.toSafe()
		if err != nil {
			return config{}, err
		}
		network = &networkStruct
	}
	return config{network, conf.Survey}, nil
}

func (conf config) writeTo(w io.Writer) error {
	var network *configNetworkStr
	if conf.Network != nil {
		networkStruct, err := conf.Network.toUnsafe()
		if err != nil {
			return err
		}
		network = &networkStruct
	}
	conv := configStr{network, conf.Survey}
	return toml.NewEncoder(w).Encode(&conv)
}
