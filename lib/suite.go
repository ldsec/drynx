package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

var PairingSuite = pairing.NewSuiteBn256()

func init() {
	cothority.Suite = PairingSuite
	libunlynx.SuiTe = PairingSuite
}
