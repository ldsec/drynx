package libdrynx

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func init() {
	libunlynx.SuiTe = bn256.NewSuiteG1()
}
