package portscan_detector

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPStream struct {
	Length        int
	Packets       []gopacket.Packet
	TransportFlow gopacket.Flow
	XLayerFlow		CrossLayerFlow
	SrcHost   string
	DstHost   string
	SrcPort   string
	DstPort   string
	HasSYN    bool
	HasACK    bool		// NOTE THAT THIS IS A NON-SYNACK ACK
	HasSYNACK bool
	HasRST    bool
	HasFIN 	  bool
	HasRSTACK bool
}

func (stream *TCPStream) AddPacket(packet gopacket.Packet) *TCPStream {

	// GET IP AND TCP LAYERS
	tcpLayer := packet.TransportLayer().(*layers.TCP)
	ipLayer := packet.NetworkLayer().(*layers.IPv4)

	// ADD THE PACKET
	stream.Length += 1
	stream.Packets = append(stream.Packets, packet)

	//fmt.Println(stream.Length)
	// LOOK FOR A CONNECTION SETUP SYN ONLY NOT A SYNACK
	if stream.Length == 1 || (tcpLayer.SYN && !tcpLayer.ACK) {
		stream.TransportFlow = packet.TransportLayer().TransportFlow()
		stream.SrcHost = ipLayer.SrcIP.String()
		stream.DstHost = ipLayer.DstIP.String()
		stream.SrcPort = tcpLayer.SrcPort.String()
		stream.DstPort = tcpLayer.DstPort.String()
		stream.HasSYN = tcpLayer.SYN
		stream.XLayerFlow = *NewCrossLayerFlow(stream.SrcHost, stream.SrcPort, stream.DstHost, stream.DstPort)
	}

	// CHECK FOR SYNACK
	if tcpLayer.SYN && tcpLayer.ACK && stream.HasSYNACK == false {
		stream.HasSYNACK = true
	}

	// CHECK FOR NON-SYN/ACK ACK
	if tcpLayer.ACK && !tcpLayer.SYN && stream.HasACK == false {
		stream.HasACK = true
	}


	// CHECK FOR NON-RST/ACK RST
	if tcpLayer.RST && !tcpLayer.ACK && stream.HasRST == false {
		stream.HasRST = true
	}

	// CHECK FOR RST/ACK
	if tcpLayer.RST && tcpLayer.ACK && stream.HasRSTACK == false {
		stream.HasRSTACK = true
	}

	// CHECK FOR FIN
	if tcpLayer.FIN && stream.HasFIN == false{
		stream.HasFIN = true
	}

	return stream

}

// BUILD A NEW TCPStream OBJECT
func NewTCPStream() *TCPStream {

	return &TCPStream{
		Length: 0,
		Packets:  []gopacket.Packet{},
		SrcHost: "",
		DstHost: "",
		SrcPort: "",
		DstPort: "",
		HasSYNACK: false,
		HasSYN: false,
		HasRST: false,
		HasACK: false,
		HasFIN: false,
	}
}

// OwnsPacket DETERMINES IF A CROSS LAYER FLOW OWNS A PACKET - ALLOWING FOR BIDIRECTIONAL STREAM REASSEMBLY
func (stream *TCPStream) OwnsPacket(p gopacket.Packet) bool {

	// GET THE STREAM'S CROSS LAYER FLOW
	clf := stream.XLayerFlow

	// GET LAYERS
	tcpLayer := p.TransportLayer().(*layers.TCP)
	ipLayer := p.NetworkLayer().(*layers.IPv4)

	// IF THE PACKET'S SOURCE AND DEST IP ADDRESSES BELONG IN THE FLOW
	sPort, dPort := tcpLayer.SrcPort.String(), tcpLayer.DstPort.String()
	sAddr, dAddr := ipLayer.SrcIP.String(), ipLayer.DstIP.String()

	// ENSURE NETWORK LAYER MATCHES
	if (clf.SrcHost == sAddr && clf.DstHost == dAddr) || (clf.SrcHost == dAddr && clf.DstHost == sAddr) {

		// NETWORK LAYER MATCHES. CHECK TRANSPORT LAYERS
		if (clf.SrcPort == sPort && clf.DstPort == dPort) || (clf.SrcPort == dPort && clf.DstPort == sPort) {
			return true
		}
	}

	return false
}