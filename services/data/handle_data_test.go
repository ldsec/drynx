package data_test

import (
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
	"testing"
	"github.com/lca1/drynx/services/data"
	"github.com/JoaoAndreSa/MedCo/lib"
)

const filename = "unlynx_test_data.txt"
const numDPs = 2
const numEntries = 10
const numEntriesFiltered = 5
const numGroupsClear = 0
const numGroupsEnc = 2
const numWhereClear = 0
const numWhereEnc = 2
const numAggrClear = 0
const numAggrEnc = 2

var numType = [...]int64{2, 5}

var testData map[string][]lib.DpClearResponse

func TestAllPossibleGroups(t *testing.T) {
	data.Groups = make([][]int64, 0)

	group := make([]int64, 0)
	data.AllPossibleGroups(numType[:], group, 0)

	log.LLvl1(data.Groups)
	numElem := 1
	for _, el := range numType {
		numElem = numElem * int(el)
	}
	assert.Equal(t, numElem, len(data.Groups), "Some elements are missing")
}

func TestGenerateData(t *testing.T) {
	testData = data.GenerateUnLynxData(numDPs, numEntries, numEntriesFiltered, numGroupsClear, numGroupsEnc,
		numWhereClear, numWhereEnc, numAggrClear, numAggrEnc, numType[:], true)
}

func TestWriteDataToFile(t *testing.T) {
	data.WriteDataToTextFile(filename, testData)
}

func TestReadDataFromFile(t *testing.T) {
	data.ReadDataFromTextFile(filename)
}

func TestCompareClearResponses(t *testing.T) {
	data.ReadDataFromTextFile(filename)
	assert.Equal(t, testData, data.ReadDataFromTextFile(filename), "Data should be the same")
}

func TestComputeExpectedResult(t *testing.T) {
	log.Lvl1(data.ComputeExpectedResult(data.ReadDataFromTextFile(filename), 1, false))
	assert.Equal(t, data.CompareClearResponses(data.ComputeExpectedResult(testData, 1, false), data.ComputeExpectedResult(data.ReadDataFromTextFile(filename), 1, false)), true, "Response should be the same")
	assert.Equal(t, data.CompareClearResponses(data.ComputeExpectedResult(testData, 1, true), data.ComputeExpectedResult(data.ReadDataFromTextFile(filename), 1, true)), true, "Response should be the same")
}
