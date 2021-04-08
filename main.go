package main

import (
	"errors"
	"fmt"
	"github.com/k-mistele/pcap_portscan_detector/portscan_detector"
	"io/ioutil"
	"strings"
)

// FUNCTION TO GET THE NAME OF A PCAP FILE IN THE PCAPS DIRECTORY
func getPCAPFilename() (string, error) {

	var filenames []string
	var selection int
	var fname string

	filenames = []string{}

	fmt.Println("Available PCAP Files:")
	fmt.Println("*********************")

	// GET LISTING OF FILES IN THE PCAP DIRECTORY
	files, err := ioutil.ReadDir("./pcaps")
	if err != nil {
		return fname, err
	}
	for _, f := range files {
		if strings.Contains(f.Name(), ".pcap") {
			filenames = append(filenames, f.Name())
		}

	}
	for idx, fname := range filenames {
		fmt.Printf("(%d) %s\n", idx+1, fname)
	}
	fmt.Println()

	// GET THE USER SELECTION
	fmt.Print("Select a PCAP to analyze: ")
	_, err = fmt.Scanf("%d", &selection)
	if err != nil {
		return fname, err
	}

	if selection < 1 || selection > len(filenames) {
		return fname, errors.New("Invalid selection!")
	}

	fname = filenames[selection-1]
	return fmt.Sprintf("./pcaps/%s", fname), nil

}

// THE TOOL ENTRYPOINT
func main() {

	// BANNER
	fmt.Println("PCAP port scan detector by Kyle Mistele and Angela Barsallo")
	fmt.Println("To analyze a pcap, place it in the './pcaps' directory")
	fmt.Println("***************************************************************")
	fmt.Println()

	// LOOP INFINITELY
	for true {
		filename, err := getPCAPFilename()
		if err != nil {
			fmt.Printf("Invalid selection: %s\n", err)
			continue
		}

		// DO THE ANALYSIS
		 err = portscan_detector.Analyze(filename)
		 if err != nil {
		 	fmt.Println(err)
		 }
		fmt.Println()
	}
}
