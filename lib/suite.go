package libdrynx

import (
	"github.com/dedis/kyber/pairing/bn256"
	"github.com/dedis/cothority"
	"github.com/lca1/unlynx/lib"
)

// SuiTe is the instantiation of the suite
//var SuiTe = bn256.NewSuiteG1()

func init() {
	cothority.Suite = bn256.NewSuiteG1()
	libunlynx.SuiTe = bn256.NewSuiteG1()
}

// SuiTe in this case is the ed25519 curve
//var SuiTe = suites.MustFind("Ed25519")

//var SuiTe = suites.MustFind("bn256.g1")

//func CurvePairingTest() bool {
//	return SuiTe.String() == "combined:bn256.G1"
//}
