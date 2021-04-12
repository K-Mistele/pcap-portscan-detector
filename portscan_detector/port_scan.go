package portscan_detector

import (
	"fmt"
	"github.com/google/gopacket"
	. "github.com/k-mistele/pcap_portscan_detector/set"
	"time"
)

// ScanType DEFINES ENUM TYPES (KIND OF) FOR DIFFERENT PORT SCAN TYPES FOR EXTENSIBILITY
type ScanType string

const (
	TCPSYNScan     ScanType = "TCP SYN Scan"
	TCPConnectScan ScanType = "TCP Connect Scan"
	UnknownScan    ScanType = "Unknown Scan Type"
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
	NetworkFlow   string
}

// determinePortScanType WILL CLASSIFY THE PortScan AS A SYN OR CONNECT SCAN.
// THIS SHOULD ONLY BE CALLED BY THE CONSTRUCTOR.
func (ps *PortScan) determinePortScanType() {

	// NOTE: THIS IS NON-IDEMPOTENT
	synScanConns, connectScanConns := 0, 0

	// LOOK FOR CONNECTIONS TO OPEN PORTS IN ALL TCP STREAMS IN THE SCAN
	for _, stream := range ps.streams {

		// SYN + SYNACK MEANS THERE'S AN OPEN PORT.
		if stream.HasSYN && stream.HasSYNACK {

			// NON-RST/ACK RST INDICATES A SYN SCAN
			if stream.HasRST && !stream.HasRSTACK {
				synScanConns += 1

				// RST/ACK INDICATES A CONNECT SCAN
			} else if stream.HasRSTACK && !stream.HasRST {
				connectScanConns += 1

				// OTHERWISE THIS IS SOMETHING DIFFERENT/MALFORMED, LOG IT
			} else {
				fmt.Printf("Malformed TCP connection %+v\n", stream.XLayerFlow)
			}
		}
	}

	// IF NO OPEN PORTS, THEN WE CAN'T IDENTIFY IF
	if synScanConns == 0 && connectScanConns == 0 {
		ps.Type = UnknownScan
	} else if synScanConns >= connectScanConns {
		ps.Type = TCPSYNScan
	} else {
		ps.Type = TCPConnectScan
	}

	fmt.Printf("Scan %s has %d SYN scan-like conns, and %d connect scan-like conns\n", ps.NetworkFlow, synScanConns, connectScanConns)
	fmt.Printf("Classifying scan %s as %v\n", ps.NetworkFlow, ps.Type)

}

// NewPortScan CONSTRUCTS A PortScan OBJECT FROM A LIST OF TCP STREAMS
func NewPortScan(attackingHost string, targetHost string, streams []*TCPStream, ports *Set) *PortScan {

	// BUILD THE PortScan STRUCT
	ps := PortScan{
		AttackingHost: attackingHost,
		TargetHost:    targetHost,
		streams:       streams,
		ScannedPorts:  ports,
		packets:       []gopacket.Packet{},
		Flows:         []gopacket.Flow{},
		NetworkFlow:   fmt.Sprintf("%s->%s", attackingHost, targetHost),
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

	// DETERMINE THE PORT SCAN TYPE FOR THE PORT SCAN
	ps.determinePortScanType()

	// TODO: DETERMINE START AND END TIME

	// RETURN THE PortScan
	return &ps

}
