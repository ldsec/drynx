package test

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"testing"
)

const TestDir = "../test"

var subdirsToAddToPATH = []string{"client", "server"}

func getEnvForTest() []string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	var toAddToPATH string
	for _, toAdd := range subdirsToAddToPATH {
		toAddToPATH += cwd + "/" + toAdd + ":"
	}

	env := os.Environ()
	for i, line := range env {
		if strings.HasPrefix(line, "PATH=") {
			env[i] = "PATH=" + toAddToPATH + line[5:]
			return env
		}
	}

	panic("no $PATH defined")
}

func TestShell(t *testing.T) {
	tests, err := ioutil.ReadDir(TestDir)
	if err != nil {
		panic(err)
	}

	testEnv := getEnvForTest()
	for _, test := range tests {
		if test.Mode()&0100 == 0 || test.IsDir() {
			continue
		}
		test := test
		t.Run(test.Name(), func(tt *testing.T) {
			tt.Parallel()
			cmd := exec.Command("./" + test.Name())
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Env = testEnv
			cmd.Dir = TestDir
			err := cmd.Run()
			if err != nil {
				tt.Fatal(err)
			}
		})
	}
}
