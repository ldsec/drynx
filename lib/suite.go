package libdrynx

import (
	"github.com/dedis/cothority"
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/lca1/unlynx/lib"
)

func init() {
	cothority.Suite = bn256.NewSuiteG1()
	libunlynx.SuiTe = bn256.NewSuiteG1()
}
