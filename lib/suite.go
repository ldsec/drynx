package libdrynx

import (
	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

// Suite is the suite used for communication
var Suite = bn256.NewSuiteG1()

func init() {
	cothority.Suite = Suite
	libunlynx.SuiTe = Suite
}

// CurvePairingTest test the type of the curve.
func CurvePairingTest() bool {
	return libunlynx.SuiTe.String() == "bn256.G1"
}
