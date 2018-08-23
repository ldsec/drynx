package lib

import (
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/kyber/pairing/bn256"
)

// TestAddRmProof tests the generation of the noise values for the differential privacy
func TestGenerateNoiseValues(t *testing.T) {
	libunlynx.SuiTe = bn256.NewSuiteG1()
	aux := GenerateNoiseValues(0, 0, 1, 0.005, 0)
	assert.Empty(t, aux)

	aux = GenerateNoiseValues(500, 0, 1, 0.005, 0)
	log.LLvl1(aux)
	log.LLvl1(len(aux))
	assert.Equal(t, len(aux), 500)

	temp := make([]float64, 0)
	for i := 0; i < 100; i++ {
		temp = append(temp, 0)
	}

	assert.Equal(t, temp, aux[:100])

	temp = make([]float64, 0)
	for i := 0; i < 19; i++ {
		temp = append(temp, 1)
		temp = append(temp, -1)
	}

	assert.Equal(t, temp, aux[100:138])

	aux = GenerateNoiseValuesScale(500, 0, 1, 0.005, 100, 60)
	log.LLvl1(aux)
}
