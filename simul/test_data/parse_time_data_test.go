package timedata

import (
	"github.com/lca1/unlynx/simul/test_data/time_data"
	"testing"
)

const filenameRead = "drynx.csv"
const filenameWrite = "drynx.txt"
const filenameToml = "../runfiles/drynx.toml"

var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
	"Simulation", "\n",
	"DataCollectionProtocol", "JustExecution", "AllProofs", "WaitTimeDPs", "BI", "Decode", "DiffPPhase", "\n",
}

func TestWriteDataFromCSVFile(t *testing.T) {
	t.Skip()
	testTimeData := timedataunlynx.ReadDataFromCSVFile(filenameRead, flags)

	timedataunlynx.CreateCSVFile(filenameWrite)
	for i := 0; i < len(testTimeData[flags[0]]); i++ {
		setup := timedataunlynx.ReadTomlSetup(filenameToml, i)
		timedataunlynx.WriteDataFromCSVFile(filenameWrite, flags, testTimeData, i, setup)
	}
}
