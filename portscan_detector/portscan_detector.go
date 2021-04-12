package portscan_detector

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/jedib0t/go-pretty/table"
	. "github.com/k-mistele/pcap_portscan_detector/set"
	"os"
	"strings"
)

// reasonableDifferentPortThreshold DEFINES THE GREATEST NUMBER OF DIFFERENT TCP PORTS A HOST MIGHT REASONABLE
// CONNECT TO WITHOUT BEING CONSIDERED MALICIOUS. THIS IS PROBABLY HIGHBALLING IT THOUGH TBH - MAYBE 80, 443, 22, 21, 139, 445
// IF THE COMPUTER IS BEING USED BY A SUPER USER
const reasonableDifferentPortThreshold = 10

// buildTransportStreams BUILDS A LIST OF BIDIRECTIONAL TRANSPORT STREAMS
func buildTransportStreams(packetSource *gopacket.PacketSource) (*[]*TCPStream, error) {

	var streams []*TCPStream
	var numPackets = 0

	// LOOP ACROSS ALL PACKETS IN THE PCAP SOURCE
	for packet := range packetSource.Packets() {

		// END CONDITION
		if packet == nil {
			return &streams, nil
		}

		// CHECK IF THE PACKET BELONGS TO AN EXISTING STREAM
		foundStreamForPacket := false
		for _, stream := range streams {

			// IF YES, ADD THE PACKET TO THE STREAM AND BREAK OUT OF THE FOR LOOP
			if stream.OwnsPacket(packet) {
				stream.AddPacket(packet)
				foundStreamForPacket = true
				break
			}
		}

		// IF STREAM NOT FOUND, MAKE A NEW ONE AND ADD IT TO THE LIST
		if !foundStreamForPacket {
			s := NewTCPStream()
			s.AddPacket(packet)
			streams = append(streams, s)
		}

		numPackets++
	}

	return &streams, nil
}

// correlateTransportStreamsToNetworkSource BUILDS A MAP OF IP ADDRESSES TOA LIST OF TCP STREAMS
func correlateTransportStreamsToNetworkSource(tcpStreams *[]*TCPStream) (*map[string][]*TCPStream, error) {

	// CREATE MAP TO CORRELATE ORIGINATING IP TO STREAMS
	m := make(map[string][]*TCPStream)

	// LOOP ACROSS STREAMS AND ASSIGN THEM TO THE MAP
	for _, stream := range *tcpStreams {

		// CHECK IF THERE'S ALREADY A MAP ENTRY
		_, exists := m[stream.SrcHost]
		if exists {
			m[stream.SrcHost] = append(m[stream.SrcHost], stream)
		} else {
			m[stream.SrcHost] = []*TCPStream{stream}
		}

	}
	return &m, nil
}

// identifyPortScans BUILDS A LIST OF PORT SCANS
func identifyPortScans(sourceHostToStreams *map[string][]*TCPStream) (*[]string, *map[string]*Set) {

	var attackingHosts []string
	targetHostToPortMap := make(map[string]*Set)

	// IDENTIFY ATTACKS BY ID A HOST IS THE SOURCE OF CONNECTIONS TO > 10 DIFFERENT PORT NUMBERS IN A SHORT AMOUNT OF TIME
	// LOOP ACROSS STREAMS BY SRC HOST
	for srcHost := range *sourceHostToStreams {
		streams := (*sourceHostToStreams)[srcHost]

		// BUILD A SET OF PORTNUMBERS THAT EACH HOST CONNECTED TO
		portNumbers := NewSet()
		for _, stream := range streams {

			// PARSE THE STRING INTO AN INT, CUTTING OFF THE GUESS AND PORT/APP NAME IF PRESENT
			//var portStr string
			//var portNo int
			//if strings.Contains(stream.DstPort, "(") {
			//	portStr = strings.Split(stream.DstPort, "(")[0]
			//} else {
			//	portStr = stream.DstPort
			//}
			//
			//// FILTER OUT EPHEMERAL PORTS - USUALLY WE CAN IGNORE THESE
			//portNo, _ = strconv.Atoi(portStr)
			//if portNo < lowestEphemeralPort {
			//	portNumbers.Add(stream.DstPort)
			//}
			portNumbers.Add(stream.DstPort)
		}

		if portNumbers.Size() >= reasonableDifferentPortThreshold {
			// IF THE SIZE IS LESS THAN 10, IT'S PROBABLY A PORT SCAN
			attackingHosts = append(attackingHosts, srcHost)

			// TODO: THIS ASSUMES ALL OF AN ATTACKER'S STREAMS ARE SCANS, WHICH IS PROBABLY NOT THE CASE.
			// TODO: FILTER OUT NON-ATTACK STREAMS
			// MAP THE TARGET HOSTS AND PORTS TOGETHER
			for _, stream := range streams {

				// ONLY GET CONNECT SCAN STREAMS
				_, exists := targetHostToPortMap[stream.DstHost]
				if exists {
					targetHostToPortMap[stream.DstHost].Add(stream.DstPort)
				} else {
					targetHostToPortMap[stream.DstHost] = NewSet()
					targetHostToPortMap[stream.DstHost].Add(stream.DstPort)
				}

			}

			// REMOVE TARGETS WITH < 10 PORTS IN SCAN SINCE IT'S LIKELY JUST A CONN ERROR
			for dstHost := range targetHostToPortMap {
				if targetHostToPortMap[dstHost].Size() < 10 {
					delete(targetHostToPortMap, dstHost)
				}
			}
		}

	}
	return &attackingHosts, &targetHostToPortMap
}

// buildPortScans BUILDS A SLICE OF PortScan OBJECTS
func buildPortScans(attackingHosts *[]string, streams *[]*TCPStream, targetHostToPortMap *map[string]*Set) *[]*PortScan {

	var portScans []*PortScan
	var networkFlows map[string]map[string][]*TCPStream // MAP SOURCE IP TO DESTINATION IP TO STREAMS

	// BUILD OUT THE NETWORK MAP
	networkFlows = make(map[string]map[string][]*TCPStream)
	for _, attackingHost := range *attackingHosts {
		networkFlows[attackingHost] = make(map[string][]*TCPStream)
	}

	// GET A SLICE OF VICTIM HOSTS
	victimHosts := mapKeys(targetHostToPortMap)

	// SEPARATE STREAMS INTO NETWORK LAYER FLOWS
	for _, stream := range *streams {

		// ONLY DO THIS FOR USEFUL STREAMS
		if contains(*attackingHosts, stream.SrcHost) && contains(*victimHosts, stream.DstHost) {
			networkFlows[stream.SrcHost][stream.DstHost] = append(networkFlows[stream.SrcHost][stream.DstHost], stream)
		}

	}

	// NOW WE HAVE END TO END NETWORK MAPPINGS SO WE CAN PROCESS THE SCAN
	for attackingHost := range networkFlows {

		for targetHost := range networkFlows[attackingHost] {
			//fmt.Printf("TransportFlow %s->%s\n", attackingHost, targetHost)

			// BUILD THE PortScan
			ps := NewPortScan(attackingHost, targetHost, networkFlows[attackingHost][targetHost], (*targetHostToPortMap)[targetHost])

			// ADD THE PortScan TO THE LIST OF PortScans
			portScans = append(portScans, ps)
		}

	}

	return &portScans
}

// printScanData WILL PRETTY-PRINT THE RESULTS OF THE SCAN DATA
func printScanData(portScans *[]*PortScan) {

	// START TO BUILD A table.Table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetTitle("TCP Port Scans")
	t.AppendHeader(table.Row{"#", "Source", "Target", "Type"})
	for idx, scan := range *portScans {
		row := []interface{}{idx + 1, scan.AttackingHost, scan.TargetHost, string(scan.Type)}
		t.AppendRow(row)
	}
	t.Render()
}

// printVerboseScanData WILL PRETTY-PRINT THE VERBOSE INFORMATION ON A SCAN
func printVerboseScanData(scan *PortScan) {
	// BUILD A TABLE
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetTitle("Port Scan Data for %s", scan.NetworkFlow)
	t.AppendHeader([]interface{}{"Field", "Value"})
	t.AppendRow([]interface{}{"Scanning Host", scan.AttackingHost})
	t.AppendRow([]interface{}{"Target Host", scan.TargetHost})
	t.AppendRow([]interface{}{"Scan Type", scan.Type})
	t.AppendRow([]interface{}{"Start Time", scan.StartTime.String()})
	t.AppendRow([]interface{}{"End Time", scan.EndTime.String()})
	t.AppendRow([]interface{}{"Elapsed Time", scan.Duration.String()})
	t.AppendRow([]interface{}{"# of Ports Scanned", scan.ScannedPorts.Size()})
	t.Render()

}

// Analyze IS A REFACTOR OF ANALYZE, WIP
func Analyze(pathToPcap string) error {

	fmt.Println("Beginning analysis! (this may take a while depending on the size of your file)...")

	handle, err := pcap.OpenOffline(pathToPcap)
	if err != nil {
		return err
	}
	if err = handle.SetBPFFilter("tcp"); err != nil {
		return err
	}

	// LOOP ACROSS PACKETS
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// BUILD TRANSPORT LAYER CONNECTIONS
	fmt.Println("Reassembling TCP Streams...")
	transportStreams, err := buildTransportStreams(packetSource)
	if err != nil {
		return err
	}
	fmt.Printf("Identified %d transport streams!\n", len(*transportStreams))
	synacks := 0
	for _, stream := range *transportStreams {
		if stream.HasSYNACK {
			synacks++
		}
	}

	//fmt.Printf("%d streams have SYN + SYN/ACKS, indicating open ports!\n", synacks)
	fmt.Println("TCP Streams reassembled! Correlating TCP streams to origin host...")

	// CORRELATE THESE STREAMS TO A LIST OF ORIGINATING HOSTS
	transportStreamBySourceHost, err := correlateTransportStreamsToNetworkSource(transportStreams)
	if err != nil {
		return err
	}
	fmt.Println("TCP streams correlated! Identifying port scans...")

	// IDENTIFY HOSTS THAT TALK TO LOTS OF DIFFERENT PORTS
	attackingHosts, targetHostToPortMaps := identifyPortScans(transportStreamBySourceHost)
	fmt.Println("Port scans identified! Aggregating scan data...")

	// BUILD PORT SCANS
	portScans := buildPortScans(attackingHosts, transportStreams, targetHostToPortMaps)
	fmt.Printf("Scan data aggregated!\n\n")
	// DO THE ACTUAL PRINTING
	printScanData(portScans)

	// PROMPT FOR FURTHER ANALYSIS
	var selection int
	var shouldContinue string

	fmt.Print("Would you like to analyze any scans in depth? (y/n) ")
	_, _ = fmt.Scanf("%s", &shouldContinue)
	for strings.ToLower(shouldContinue) == "y" {

		// GET THE NUMBER OF THE PORT SCAN TO ANALYZE
		fmt.Print("Enter the number of a port scan to view details: ")
		_, _ = fmt.Scanf("%d", &selection)
		fmt.Println()

		// GRAB THE SCAN AND PRINT VERBOSE INFORMATION
		scan := (*portScans)[selection-1]
		printVerboseScanData(scan)

		// PROMPT TO PRINT PORTS
		fmt.Print("Print all scanned ports? (y/n) ")
		var shouldPrintScannedPorts string
		_, _ = fmt.Scanf("%s", &shouldPrintScannedPorts)
		if strings.ToLower(shouldPrintScannedPorts) == "y" {
			fmt.Println(scan.ScannedPorts.Items())
		}

		// PROMPT TO CONTINUE
		fmt.Printf("Would you like to analyze another scan? (y/n) ")
		_, _ = fmt.Scanf("%s", &shouldContinue)
	}

	return nil
}
