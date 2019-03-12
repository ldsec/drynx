package libdrynx

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"github.com/lca1/unlynx/lib"
)

func init() {
	cothority.Suite = bn256.NewSuiteG1()
	libunlynx.SuiTe = bn256.NewSuiteG1()
}
