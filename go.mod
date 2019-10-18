module github.com/ldsec/drynx

go 1.13

// uncomment when running mininet
//replace github.com/ldsec/unlynx => ../unlynx
//replace go.dedis.ch/onet/v3 => ../../../go.dedis.ch/onet

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
	github.com/pelletier/go-toml v1.5.1-0.20191009163356-e87c92d4f423
	github.com/smartystreets/goconvey v0.0.0-20190731233626-505e41936337 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/tonestuff/quadratic v0.0.0-20141117024252-b79de8af2377
	github.com/urfave/cli v1.22.1
	go.dedis.ch/cothority/v3 v3.3.1
	go.dedis.ch/kyber/v3 v3.0.7
	go.dedis.ch/onet/v3 v3.0.26
	go.dedis.ch/onet/v4 v4.0.0-pre1
	go.dedis.ch/protobuf v1.0.10 // indirect
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/sys v0.0.0-20191010194322-b09406accb47 // indirect
	gonum.org/v1/gonum v0.0.0-20191017124610-65cdd97ca8b9
	gopkg.in/satori/go.uuid.v1 v1.2.0
)

replace go.dedis.ch/onet/v4 => ../onet
