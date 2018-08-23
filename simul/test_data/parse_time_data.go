package timedata

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/dedis/onet/log"
)

const spacing = 50

// addSpaces add a string with a specific number of spaces until it reaches length
func addSpaces(length int, final int) string {
	spaces := ""

	for i := 0; i < final-length; i++ {
		spaces += " "
	}
	return spaces
}

// CreateCSVFile creates and saves a CSV file
func CreateCSVFile(filename string) {
	var fileHandle *os.File
	var err error

	fileHandle, err = os.Create(filename)

	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()
}

// ReadTomlSetup reads the .toml and parses the different properties (e.g. Hosts)
func ReadTomlSetup(filename string, setupNbr int) map[string]string {
	var parameters []string

	setup := make(map[string]string)

	fileHandle, err := os.Open(filename)

	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()

	scanner := bufio.NewScanner(fileHandle)

	flag := false
	pos := 0
	for scanner.Scan() {
		line := scanner.Text()

		c := strings.Split(line, ", ")

		if flag == true {
			if pos == setupNbr {
				for i, el := range c {
					setup[parameters[i]] = el
				}
				break
			}
			pos++
		}

		if c[0] == "Hosts" {
			flag = true
			parameters = c
		}

	}

	return setup
}

// WriteDataFromCSVFile gets the flags and the time values (parsed from the CSV file) and writes everything into a nice .txt file
func WriteDataFromCSVFile(filename string, flags []string, testTimeData map[string][]string, pos int, setup map[string]string) {

	var fileHandle *os.File
	var err error

	fileHandle, err = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)

	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()

	writer := bufio.NewWriter(fileHandle)

	_, err = fileHandle.WriteString("\n\n\n|-------------------------------------------------------------------------|\n" +
		"|----------------------------- SIMULATION #" + fmt.Sprintf("%v", pos+1) + " -----------------------------|\n" +
		"|-------------------------------------------------------------------------|\n\n\n")

	if err != nil {
		log.Fatal(err)
	}

	for k, v := range setup {
		_, err = fileHandle.WriteString(k + ":" + addSpaces(len(k), spacing) + v + "\n")

		if err != nil {
			log.Fatal(err)
		}
	}
	_, err = fileHandle.WriteString("\n")

	if err != nil {
		log.Fatal(err)
	}

	for _, value := range flags {
		var err error

		if value != "\n" {
			if len(testTimeData[value]) > 0 {
				_, err = fileHandle.WriteString(value + ":" + addSpaces(len(value), spacing) + testTimeData[value][pos] + "\n")
			} else {
				_, err = fileHandle.WriteString(value + ":" + addSpaces(len(value), spacing) + "\n")
			}
		} else {
			_, err = fileHandle.WriteString(value)
		}

		if err != nil {
			log.Fatal(err)
		}
	}

	defer writer.Flush()
}

// ReadDataFromCSVFile reads a CSV
func ReadDataFromCSVFile(filename string, sep string) [][]string {
	fileHandle, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()

	r := bufio.NewReader(fileHandle)

	lines := make([][]string, 0)

	// read tags of csv
	line, err := Readln(r)
	if err != nil {
		log.Fatal(err)
	}
	// the data lines
	for err == nil {
		tokensLine := strings.Split(line, sep)
		lines = append(lines, tokensLine)
		line, err = Readln(r)
	}

	return lines
}

// Readln returns a single line (without the ending \n)
// from the input buffered reader.
// An error is returned if there is an error with the
// buffered reader.
func Readln(r *bufio.Reader) (string, error) {
	var (
		isPrefix       = true
		err      error = nil
		line, ln []byte
	)
	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}
	return string(ln), err
}

// ParseDataFromCSVFile reads data from the CSV file where the time values are stored and re-arranges everything in a key-value map
func ParseDataFromCSVFile(lines [][]string, flags []string) map[string][]string {
	/*fileHandle, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer fileHandle.Close()

	lines, err := csv.NewReader(fileHandle).ReadAll()
	if err != nil {
		log.Fatal(err)
	}*/

	result := make(map[string][]string)

	for line := 1; line < len(lines); line++ {

		for i, l := range lines[line] {

			s := strings.Split(lines[0][i], "_")

			for _, el := range s {

				if stringInSlice(el, flags) {
					if len(s) >= 2 {
						if s[len(s)-1] == "sum" && s[len(s)-2] == "wall" { //Only the time values that have wall in the end matter
							if _, ok := result[el]; ok && len(result[el]) == line {
								result[el][line-1] += ", " + l
							} else {
								result[el] = append(result[el], l)
							}
							continue
						}
					} else {
						result[el] = append(result[el], l)
						continue
					}
				}
			}
		}
	}

	return result
}

// stringInSlice checks if a string is inside an array of strings
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
