package provider

import "github.com/ldsec/drynx/lib"

// Loader is the way to retrieve local data.
type Loader interface {
	// Provide returns the queried rows to encode.
	// Returns a matrix of len Query.Operation.NbrInput
	Provide(libdrynx.Query) ([][]float64, error)
}
