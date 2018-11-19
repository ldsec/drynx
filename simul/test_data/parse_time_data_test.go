package timedata

import (
	"testing"
)

const filenameRead = "drynx.csv"
const filenameWrite = "drynxFC.txt"
const filenameToml = "../runfiles/drynx.toml"

var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
	"Simulation", "\n",
	"DataCollectionProtocol", "JustExecution", "AllProofs", "WaitTimeDPs", "BI", "Decode", "\n",
}

func TestReadTomlSetup(t *testing.T) {
	ReadTomlSetup(filenameToml, 1)
}

func TestReadDataFromCSV(t *testing.T) {
	ReadDataFromCSVFile(filenameRead, ",")
}

func TestWriteDataFromCSVFile(t *testing.T) {
	lines := ReadDataFromCSVFile(filenameRead, ",")
	testTimeData := ParseDataFromCSVFile(lines, flags)

	CreateCSVFile(filenameWrite)
	for i := 0; i < len(testTimeData[flags[0]]); i++ {
		setup := ReadTomlSetup(filenameToml, i)
		WriteDataFromCSVFile(filenameWrite, flags, testTimeData, i, setup)
	}
}
