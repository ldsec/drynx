module github.com/ldsec/drynx

go 1.12

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/alex-ant/gomath v0.0.0-20160516115720-89013a210a82
	github.com/btcsuite/goleveldb v1.0.0
	github.com/cdipaolo/goml v0.0.0-20190412180403-e1f51f713598
	github.com/coreos/bbolt v1.3.3
	github.com/fanliao/go-concurrentMap v0.0.0-20141114143905-7d2d7a5ea67b
	github.com/ldsec/unlynx v1.4.0
	github.com/montanaflynn/stats v0.5.0
	github.com/stretchr/testify v1.4.0
	github.com/tonestuff/quadratic v0.0.0-20141117024252-b79de8af2377
	go.dedis.ch/cothority/v3 v3.2.0
	go.dedis.ch/kyber/v3 v3.0.5
	go.dedis.ch/onet/v3 v3.0.24
	golang.org/x/crypto v0.0.0-20190923035154-9ee001bba392
	gonum.org/v1/gonum v0.0.0-20190923124727-d1098a519538
	gopkg.in/satori/go.uuid.v1 v1.2.0
)

replace github.com/ldsec/unlynx => ../unlynx

replace go.dedis.ch/onet/v3 => ../../../go.dedis.ch/onet
