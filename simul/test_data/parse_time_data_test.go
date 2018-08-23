package timedata_test

import (
	"testing"

	"github.com/lca1/unlynx/simul/test_data/time_data"
)

const filenameRead = "../lemal.csv"
const filenameWrite = "lemalBand40.txt"
const filenameToml = "../../runfiles/lemalServersScaling.toml"

var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
	"Simulation", "\n",
	"DataCollectionProtocol", "JustExecution", "AllProofs", "WaitTimeDPs", "BI", "Decode", "\n",
}

func TestReadTomlSetup(t *testing.T) {
	timedata.ReadTomlSetup(filenameToml, 1)
}

func TestReadDataFromCSV(t *testing.T) {
	timedata.ReadDataFromCSVFile(filenameRead, ",")
}

func TestWriteDataFromCSVFile(t *testing.T) {
	lines := timedata.ReadDataFromCSVFile(filenameRead, ",")
	testTimeData := timedata.ParseDataFromCSVFile(lines, flags)

	timedata.CreateCSVFile(filenameWrite)
	for i := 0; i < len(testTimeData[flags[0]]); i++ {
		setup := timedata.ReadTomlSetup(filenameToml, i)
		timedata.WriteDataFromCSVFile(filenameWrite, flags, testTimeData, i, setup)
	}
}
