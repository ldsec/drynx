module github.com/ldsec/drynx

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/alex-ant/gomath v0.0.0-20160516115720-89013a210a82
	github.com/btcsuite/goleveldb v1.0.0
	github.com/cdipaolo/goml v0.0.0-20190412180403-e1f51f713598
	github.com/coreos/bbolt v1.3.3
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/fanliao/go-concurrentMap v0.0.0-20141114143905-7d2d7a5ea67b
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/ldsec/unlynx v1.4.0
	github.com/montanaflynn/stats v0.5.0
	github.com/pelletier/go-toml v1.6.0
	github.com/smartystreets/goconvey v1.6.4 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/tonestuff/quadratic v0.0.0-20141117024252-b79de8af2377
	github.com/urfave/cli v1.22.1
	go.dedis.ch/cothority/v3 v3.3.2
	go.dedis.ch/kyber/v3 v3.0.8
	go.dedis.ch/onet/v3 v3.0.26
	go.etcd.io/bbolt v1.3.4
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf
	golang.org/x/sys v0.0.0-20200331124033-c3d80250170d // indirect
	gonum.org/v1/gonum v0.6.0
	gopkg.in/satori/go.uuid.v1 v1.2.0
)

// uncomment when running mininet
//replace github.com/ldsec/unlynx => ../unlynx
//replace go.dedis.ch/onet/v3 => ../../../go.dedis.ch/onet
