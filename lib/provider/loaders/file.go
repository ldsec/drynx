package loaders

import (
	"encoding/csv"
	"errors"
	"fmt"
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
	if query.Operation.NbrInput != len(query.Selector) {
		return nil, errors.New("malformed query")
	}

	_, err := f.file.Seek(0, os.SEEK_SET)
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(&f.file)
	reader.Comma = '\t'

	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	if reader.FieldsPerRecord < query.Operation.NbrInput {
		return nil, errors.New("not enough column in CSV")
	}

	selectorIndexes := make([]uint, 0, len(query.Selector))
	for i, s := range query.Selector {
		for j, h := range header {
			if s == libdrynx.ColumnID(h) {
				selectorIndexes = append(selectorIndexes, uint(j))
				break
			}
		}
		if len(selectorIndexes) != i+1 {
			return nil, fmt.Errorf("unable to find '%s' in CSV header", s)
		}
	}

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	ret := make([][]float64, query.Operation.NbrInput)
	for i, index := range selectorIndexes {
		arr := make([]float64, len(records))
		for j, r := range records {
			arr[j], err = strconv.ParseFloat(r[index], 64)
			if err != nil {
				return nil, err
			}
		}
		ret[i] = arr
	}

	return ret, nil
}
