package main

import (
	"io"

	kyber_encoding "go.dedis.ch/kyber/v3/util/encoding"
	kyber_key "go.dedis.ch/kyber/v3/util/key"
	onet_network "go.dedis.ch/onet/v3/network"

	drynx_lib "github.com/ldsec/drynx/lib"

	"github.com/pelletier/go-toml"
)

type configDataProviderFileLoader struct {
	Path string
}
type configDataProvider struct {
	FileLoader *configDataProviderFileLoader
	Random     *struct{}
}
type config struct {
	Address onet_network.Address
	URL     string
	Key     kyber_key.Pair

	DataProvider  *configDataProvider
	ComputingNode *struct{}
	VerifyingNode *struct{}
}

type keyPairStr struct {
	Public  string
	Private string
}
type configStr struct {
	Address onet_network.Address
	URL     string
	Key     keyPairStr

	DataProvider  *configDataProvider
	ComputingNode *struct{}
	VerifyingNode *struct{}
}

func keyPairToUnsafe(kp kyber_key.Pair) (keyPairStr, error) {
	pub, err := kyber_encoding.PointToStringHex(drynx_lib.Suite, kp.Public)
	if err != nil {
		return keyPairStr{}, err
	}

	priv, err := kyber_encoding.ScalarToStringHex(drynx_lib.Suite, kp.Private)
	if err != nil {
		return keyPairStr{}, err
	}

	return keyPairStr{
		Public:  pub,
		Private: priv,
	}, nil
}

func (kp keyPairStr) toSafe() (kyber_key.Pair, error) {
	pub, err := kyber_encoding.StringHexToPoint(drynx_lib.Suite, kp.Public)
	if err != nil {
		return kyber_key.Pair{}, err
	}

	priv, err := kyber_encoding.StringHexToScalar(drynx_lib.Suite, kp.Private)
	if err != nil {
		return kyber_key.Pair{}, err
	}

	return kyber_key.Pair{
		Public:  pub,
		Private: priv,
	}, nil
}

func readConfigFrom(r io.Reader) (config, error) {
	var conf configStr
	err := toml.NewDecoder(r).Decode(&conf)

	key, err := conf.Key.toSafe()
	if err != nil {
		return config{}, err
	}

	return config{
		conf.Address,
		conf.URL,
		key,

		conf.DataProvider,
		conf.ComputingNode,
		conf.VerifyingNode,
	}, nil
}

func (conf config) writeTo(w io.Writer) error {
	key, err := keyPairToUnsafe(conf.Key)
	if err != nil {
		return err
	}

	conv := configStr{
		conf.Address,
		conf.URL,
		key,

		conf.DataProvider,
		conf.ComputingNode,
		conf.VerifyingNode,
	}

	return toml.NewEncoder(w).Encode(conv)
}
