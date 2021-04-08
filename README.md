# pcap-portscan-detector

## Install Dependencies
1. Golang >= 1.15
   * https://golang.org/doc/install
   * do _not_ install with a package manager, as you may get the wrong version
2. libpcap
    * Windows: https://www.winpcap.org/
    * Linux: `sudo apt-get install libpcap-dev`
   
## Running the Project
* drop any pcap files to analyze in the `pcaps/` directory
* Install go dependencies: `go get`
* Run the program: `go run main.go