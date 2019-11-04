package loaders

import (
	"math/rand"

	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/provider"
)

type random struct{}

// NewRandom create a Loader of random values.
func NewRandom() (provider.Loader, error) {
	return random{}, nil
}

func (random) Provide(query libdrynx.Query) ([][]float64, error) {
	ret := make([][]float64, query.Operation.NbrInput)

	min, max := query.DPDataGen.GenerateDataMin, query.DPDataGen.GenerateDataMax

	for i := range ret {
		arr := make([]float64, query.DPDataGen.GenerateRows)
		for j := range arr {
			arr[j] = float64(min + rand.Int63n(max-min))
		}
		ret[i] = arr
	}
	return ret, nil
}
