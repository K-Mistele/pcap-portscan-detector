package portscan_detector

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCPStream struct {
	Length    int
	Packets   []gopacket.Packet
	Flow      gopacket.Flow
	SrcHost   string
	DstHost   string
	SrcPort   string
	DstPort   string
	HasSYN    bool
	HasACK    bool
	HasSYNACK bool
	HasRST    bool
}

func (stream TCPStream) AddPacket(packet gopacket.Packet) *TCPStream {

	// GET IP AND TCP LAYERS
	tcpLayer := packet.TransportLayer().(*layers.TCP)
	ipLayer := packet.NetworkLayer().(*layers.IPv4)

	// ADD THE PACKET
	stream.Length += 1
	stream.Packets = append(stream.Packets, packet)

	//fmt.Println(stream.Length)
	if stream.Length == 1 || tcpLayer.SYN {
		stream.Flow = packet.TransportLayer().TransportFlow()
		stream.SrcHost = ipLayer.SrcIP.String()
		stream.DstHost = ipLayer.DstIP.String()
		stream.SrcPort = tcpLayer.SrcPort.String()
		stream.DstPort = tcpLayer.DstPort.String()
		stream.HasACK = tcpLayer.ACK
		stream.HasRST = tcpLayer.RST
		stream.HasSYN = tcpLayer.SYN
		stream.HasSYNACK = tcpLayer.SYN && tcpLayer.ACK
	}

	// CHECK FOR ACK
	if tcpLayer.ACK && stream.HasACK == false {
		stream.HasACK = true
	}

	// CHECK FOR SYNACK
	if tcpLayer.SYN && tcpLayer.ACK && stream.HasSYNACK == false {
		stream.HasSYNACK = true
	}

	// CHECK FOR RST
	if tcpLayer.RST && stream.HasRST == false {
		stream.HasRST = true
	}

	return &stream

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
	}
}
