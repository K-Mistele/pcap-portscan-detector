package portscan_detector

import (
	"github.com/google/gopacket"
	. "github.com/k-mistele/pcap_portscan_detector/set"
	"time"
)

// ScanType DEFINES ENUM TYPES (KIND OF) FOR DIFFERENT PORT SCAN TYPES FOR EXTENSIBILITY
type ScanType string
const (
	TCPSYNScan 		ScanType = "TCP SYN Scan"
	TCPConnectScan	ScanType = "TCP Connect Scan"
)

// PortScan REPRESENTS A PORT SCAN. CONTAINS A LIST OF PORTS, ETC.
type PortScan struct {
	AttackingHost string
	TargetHost    string
	ScannedPorts  *Set
	StartTime     time.Time
	EndTime       time.Time
	Type          ScanType
	packets       []gopacket.Packet
	streams       []*TCPStream
	Flows         []gopacket.Flow
}

// determinePortScanType WILL CLASSIFY THE PortScan AS A SYN OR CONNECT SCAN. THIS SHOULD ONLY BE CALLED BY THE CONSTRUCTOR.
func (ps *PortScan) determinePortScanType() {

	// NOTE: THIS IS NON-IDEMPOTENT
	//synScanConns, connectScanConns := 0, 0

	for _, stream := range ps.streams {

		// SYN + SYNACK MEANS THERE'S AN OPEN PORT.
		if stream.HasSYN && stream.HasSYNACK {

		}
	}

	// TODO: LOOK FOR SYN SCANS BY LARGE VOLUME OF SYN & SHORT CONNECTIONS
}



// NewPortScan CONSTRUCTS A PortScan OBJECT FROM A LIST OF TCP STREAMS
func NewPortScan(attackingHost string, targetHost string, streams []*TCPStream, ports *Set) *PortScan {

	// BUILD THE PortScan STRUCT
	ps := PortScan {
		AttackingHost: attackingHost,
		TargetHost:    targetHost,
		streams:       streams,
		ScannedPorts:  ports,
		packets:       []gopacket.Packet{},
		Flows:         []gopacket.Flow{},
	}

	// PROCESS EACH TCPStream STRUCT AND AGGREGATE THE INFO INTO THE PortScan struct
	for _, stream := range streams {

		// ADD THE TCPStream's DESTINATION PORT TO THE SET OF SCANNED PORTS
		ps.ScannedPorts.Add(stream.DstPort)

		// ADD THE TCPStream's PACKETS TO THE LIST OF PACKETS
		ps.packets = append(ps.packets, stream.Packets...)

		// APPEND THE FLOWS
		ps.Flows = append(ps.Flows, stream.TransportFlow)
	}


	// TODO: DETERMINE THE SCAN TYPE
	ps.determinePortScanType()

	// RETURN THE PORTSCAN
	return &ps

}