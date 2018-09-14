package libdrynx

import (
	"github.com/dedis/onet/log"
	"github.com/r0fls/gostats"
	"math"
)

// GenerateNoiseValues generates a number of n noise values from a given probabilistic distribution
func GenerateNoiseValues(n int64, mean, b, quanta, limit float64) []float64 {
	return GenerateNoiseValuesScale(n, mean, b, quanta, 1, limit)
}

// GenerateNoiseValuesScale generates a number of n noise values from a given probabilistic distribution
func GenerateNoiseValuesScale(n int64, mean, b, quanta, scale, limit float64) []float64 {
	laplace := stats.Laplace(mean, b)

	if limit != 0.0 && quanta != 0.0 {
		log.LLvl1("Both size and limit defined --> uses quanta")
	} else if quanta == 0.0 {
		sumToLim := 0.0
		for i := 0.0; i < limit; i = i + 1/scale {
			if i == 0.0 {
				sumToLim = laplace.Pdf(i)
			} else {
				sumToLim = sumToLim + 2*laplace.Pdf(i)
			}

		}
		quanta = sumToLim / float64(n)
	}

	noise := make([]float64, 0)

	start := 0.0
	countOnes := 0
	for int64(len(noise)) < n {
		val := laplace.Pdf(float64(start))
		rep := math.Ceil(val / quanta)
		count := 0
		for i := 0; i < int(rep); i++ {
			if start == 0 {
				noise = append(noise, float64(start*scale))
			} else {
				noise = append(noise, float64(start*scale))
				noise = append(noise, float64(0-start*scale))
			}
			count++

			if int64(len(noise)) >= n {
				break
			}
		}
		start = start + 1/scale

		if count == 1 {
			countOnes = countOnes + 1
		}
	}
	return noise[:n]
}
