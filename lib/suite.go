package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing"
)

// PairingSuite represents the suite being used for all of the protocols.
var PairingSuite = pairing.NewSuiteBn256()

func init() {
	cothority.Suite = PairingSuite
	libunlynx.SuiTe = PairingSuite
}
