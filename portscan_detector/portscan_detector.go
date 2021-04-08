package portscan_detector

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	. "github.com/k-mistele/pcap_portscan_detector/set"
)

// DETERMINE IF A TCP STREAM IS A SCAN
func isScanStream( stream *TCPStream) bool {

	if stream.HasSYN && !stream.HasACK && stream.HasRST {
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

	m := make(map[string] []string)
	victimPortMap = &m

	// LOOP ACROSS TCP STREAMS
	for flow := range (*tcpStreams) {

		// IDENTIFY LIKELY SCAN STREAMS
		stream := (*tcpStreams)[flow]
		if isScanStream(stream) {
			attackingHosts.Add(stream.SrcHost)
			victimHosts.Add(stream.DstHost)
			fmt.Printf("%s:%s -> %s:%s\n", stream.SrcHost, stream.SrcPort, stream.DstHost, stream.DstPort)
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

// PERFORM ANALYSIS
func Analyze(pathToPcap string) error {

	// OPEN THE PCAP FILE
	if handle, err := pcap.OpenOffline(pathToPcap); err != nil {
		return err
	} else {
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

		// COUNT PACKETS AND PERCENTAGE OF CONNECTIONS THAT HAVE ONLY A SYN
		synOnly := 0
		oneOnly := 0
		for stream := range *tcpStreams {
			s := (*tcpStreams)[stream]
			if s.HasSYN && !s.HasACK {
				synOnly += 1
			} else if s.Length == 1 {
				oneOnly += 1
			}
		}
		fmt.Printf("%d streams only have a SYN and are therefore probably port scans\n", synOnly)
		fmt.Printf("%d additional streams only have one packet, and are therefore probably port scans\n", oneOnly)
		fmt.Printf("%f percent of streams are port scans!\n", (float32(synOnly+oneOnly)/float32(len(*tcpStreams)))*100.0)

		// PERFORM TARGET IDENTIFICATION
		attackingHosts, victimHosts, victimPorts, victimPortMap := identifyTargets(tcpStreams)
		fmt.Printf("Attacking Hosts: %v\n", attackingHosts.Items())
		fmt.Printf("Victim hosts: %v\n", victimHosts.Items())
		fmt.Printf("Victim Ports: %v\n", victimPorts.Items())
		fmt.Printf("Victim Port map: %v\n", victimPortMap)

	}

	return nil
}
