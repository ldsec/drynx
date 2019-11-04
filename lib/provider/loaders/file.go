package loaders

import (
	"encoding/csv"
	"errors"
	"os"
	"strconv"

	"github.com/ldsec/drynx/lib"
	"github.com/ldsec/drynx/lib/provider"
)

type fileLoader struct {
	file os.File
}

// NewFileLoader creates a Loader backing the file found at the given path.
func NewFileLoader(path string) (provider.Loader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return fileLoader{*file}, nil
}

func (f fileLoader) Provide(query libdrynx.Query) ([][]float64, error) {
	_, err := f.file.Seek(0, os.SEEK_SET)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(&f.file)
	reader.Comma = '\t'
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if reader.FieldsPerRecord < query.Operation.NbrInput {
		return nil, errors.New("not enough column for the operation")
	}

	ret := make([][]float64, query.Operation.NbrInput)
	for i := range ret {
		arr := make([]float64, len(records))
		for j, r := range records {
			arr[j], err = strconv.ParseFloat(r[i], 64)
			if err != nil {
				return nil, err
			}
		}
		ret[i] = arr
	}

	return ret, nil
}
