package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
)

var PairingSuite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	cothority.Suite = PairingSuite
	libunlynx.SuiTe = PairingSuite
}
