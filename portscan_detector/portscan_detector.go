package portscan_detector

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	. "github.com/k-mistele/pcap_portscan_detector/set"
	"strings"
	"strconv"
)

const reasonableDifferentPortThreshhold = 10
const lowestEphemeralPort = 32768 // IANA SUGGESTS 49152, BUT LOTS OF LINUX KERNELS USE 32768

// DETERMINE IF A TCP STREAM IS A SCAN
func isScanStream(stream *TCPStream) bool {

	// IF HTTP/S IS THE SOURCE, PROBABLY NOT A PORT SCAN SINCE THAT'D COME FROM AN EPHEMERAL QUIRK.
	// THIS TRIES TO AVOID A QUIRK WITH THE PROTOCOL
	if strings.Contains(stream.SrcPort, "http") {
		return false
	}

	// LOOK FOR MALFORMED TCP CONNECTION SETUP AND TEARDOWN
	if !stream.HasSYN || !stream.HasACK || !stream.HasFIN {
		return true
	}

	// LOOK FOR SHORT STREAMS WITH AN RST INDICATING AN ERROR
	if stream.Length < 5 && stream.HasRST {
		return true
	}

	return false

}

// BUILD OUT A MAP OF TCP FLOWS
func buildTCPStreams(packetSource *gopacket.PacketSource) (*map[gopacket.Flow]*TCPStream, error) {

	tcpStreams := make(map[gopacket.Flow]*TCPStream)

	// SORT EACH gopacket.Packet INTO A map[gopacket.Flow] []gopacket.Packet
	numPackets := 0
	for packet := range packetSource.Packets() {

		if packet == nil {
			return &tcpStreams, nil
		}

		// GET TRANSPORT LAYER DATA
		tcp := packet.TransportLayer().(*layers.TCP)
		flow := tcp.TransportFlow()
		_, exists := tcpStreams[tcp.TransportFlow()]
		if exists {
			tcpStreams[flow] = tcpStreams[flow].AddPacket(packet)
		} else {
			tcpStreams[flow] = NewTCPStream()
			tcpStreams[flow] = tcpStreams[flow].AddPacket(packet)
		}
		//fmt.Println(tcpStreams[tcp.TransportFlow()].Length)

		numPackets += 1

	}

	flowLengths := []int{}
	for flow := range tcpStreams {
		flowLengths = append(flowLengths, (tcpStreams)[flow].Length)
	}
	fmt.Printf("Counted %d packets\n", numPackets)
	return &tcpStreams, nil
}

// IDENTIFY ATTACKER AND VICTIM HOSTS AND PORTS
func identifyTargets(tcpStreams *map[gopacket.Flow]*TCPStream) (attackingHosts Set, victimHosts Set, victimPorts Set, victimPortMap *map[string][]string) {

	m := make(map[string][]string)
	victimPortMap = &m

	// LOOP ACROSS TCP STREAMS
	for flow := range *tcpStreams {

		// IDENTIFY LIKELY SCAN STREAMS
		stream := (*tcpStreams)[flow]
		//if stream.DstHost == "142.250.113.113" && stream.SrcPort == "34384" {
		//	for i := range stream.Packets {
		//
		//		tcpPacket := stream.Packets[i].TransportLayer().(*layers.TCP)
		//
		//		//fmt.Printf("%+v\n", tcpPacket)
		//		//fmt.Printf("%+v\n", *stream)
		//	}
		//}
		if isScanStream(stream) {
			attackingHosts.Add(stream.SrcHost)
			victimHosts.Add(stream.DstHost)
			//fmt.Printf("%s:%s -> %s:%s\n", stream.SrcHost, stream.SrcPort, stream.DstHost, stream.DstPort)
			victimPorts.Add(stream.DstPort)

			_, exists := (*victimPortMap)[stream.DstHost]
			if exists {
				(*victimPortMap)[stream.DstHost] = append((*victimPortMap)[stream.DstHost], stream.DstPort)
			} else {
				(*victimPortMap)[stream.DstHost] = []string{}
				(*victimPortMap)[stream.DstHost] = append((*victimPortMap)[stream.DstHost], stream.DstPort)
			}
		}

	}

	return
}

// CORRELATE EACH HOST WITH A LIST OF TCP STREAMS THAT IT IS THE SOURCE OF
func correlateStreamsToHosts(tcpStreams *map[gopacket.Flow]*TCPStream) (*map[string][]*TCPStream, error) {

	// CREATE MAP TO CORRELATE ORIGINATING IP TO STREAMS
	m := make(map[string][]*TCPStream)

	// LOOP ACROSS STREAMS AND ASSIGN THEM TO MAP
	for flow := range *tcpStreams {
		stream := (*tcpStreams)[flow]

		// CHECK TO SEE IF THE SRC HOST HAS AN ENTRY IN THE MAP
		_, exists := m[stream.SrcHost]
		if exists {

			// IF THERE'S AN ENTRY IN THE MAP, ADD THE STREAM TO THE LIST OF STREAMS
			m[stream.SrcHost] = append(m[stream.SrcHost], stream)
		} else {

			// OTHERWISE, CREATE THE LIST AND THEN ADD THE STREAM
			m[stream.SrcHost] = []*TCPStream{stream}
		}

	}

	return &m, nil
}

// IDENTIFY CONNECT SCANS
func identifyScans(tcpStreamsBySrcHost *map[string][]*TCPStream) (*[]string, *map[string]*Set) {

	var attackingHosts []string
	targetHostToPortMap := make(map[string]*Set)

	// IDENTIFY ATTACKS BY ID A HOST IS THE SOURCE OF CONNECTIONS TO > 10 DIFFERENT PORT NUMBERS IN A SHORT AMOUNT OF TIME
	// THIS WOULD PROBABLY BE A TCP CONNECT SCAN
	// LOOP ACROSS STREAMS BY SRC HOST
	for srcHost := range *tcpStreamsBySrcHost {
		streams := (*tcpStreamsBySrcHost)[srcHost]

		// BUILD A LIST OF TARGET PORTS FOR EACH SRC HOST
		portNumbers := Set{}
		for _, stream := range streams {

			// MAKE SURE WE AREN'T ADDING EPHEMERAL PORTS SINCE THOSE MAY BE USED BY HTTP CONNECTIONS AND FTP

			// PARSE THE STRING INTO AN INT, CUTTING OFF THE GUESS AND PORT/APP NAME IF IT'S PRESENT
			var portStr string
			var portNo int
			if strings.Contains(stream.DstPort, "(") {
				portStr = strings.Split(stream.DstPort, "(")[0]
			} else {
				portStr = stream.DstPort
			}

			portNo, _ = strconv.Atoi(portStr)
			if portNo < lowestEphemeralPort {
				portNumbers.Add(stream.DstPort)
			}

		}

		// IF THERE ARE MORE THAN 10 DIFFERENT DESTINATION PORTS FROM A SOURCE HOST, IT'S PROBABLY AN ATTACKER
		if portNumbers.Size() >= reasonableDifferentPortThreshhold {

			// MARK IT AS AN ATTACKER
			attackingHosts = append(attackingHosts, srcHost)
			fmt.Printf("%s scanned the following Ports: %v\n", srcHost, portNumbers.Items())

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

// PERFORM ANALYSIS
func Analyze(pathToPcap string) error {

	// OPEN THE PCAP FILE
	if handle, err := pcap.OpenOffline(pathToPcap); err != nil {
		return err
	} else {

		// FILTER FOR TCP PACKETS
		if err = handle.SetBPFFilter("tcp"); err != nil {
			return err
		}

		// LOOP ACROSS PACKETS
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		// BUILD FLOWS
		tcpStreams, err := buildTCPStreams(packetSource)
		if err != nil {
			return err
		}

		var flowLengths []int
		for stream := range *tcpStreams {
			flowLengths = append(flowLengths, (*tcpStreams)[stream].Length)
		}

		// CORRELATE TCP STREAMS TO THE ORIGINATING HOST
		tcpStreamsBySrcHost, err := correlateStreamsToHosts(tcpStreams)
		if err != nil {
			return err
		}

		// IDENTIFY HOSTS THAT TALK TO LOTS OF DIFFERENT PORTS
		var attackingHosts *[]string // LIST OF SRC IPS
		var targetHostToPortMap *map[string]*Set
		attackingHosts, targetHostToPortMap = identifyScans(tcpStreamsBySrcHost)

		fmt.Printf("Attacking hosts: %v\n", attackingHosts)
		fmt.Println("Target Host to port map: \n")
		for targetHost := range *targetHostToPortMap {
			fmt.Printf("%s: %+v\n", targetHost, (*targetHostToPortMap)[targetHost].Items())
		}
		// TODO: PRINT OUTPUT IN A PRETTY FORMAT

		// TODO: IDENTIFY CONNECT SCAN BY MAPPING CONNS TO HOST, LOOK FOR LOTS OF RST'S, MAYBE > 5% OF CONNS
		// TODO: IDENTIFY SYN SCANS BY MAPPING CONNS TO HOST, LOOK FOR LOTS OF SYN'S W/O HANDSHAKE AND A SHORT STREAM

	}

	return nil
}
