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
	Duration      time.Duration
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

	//fmt.Printf("Scan %s has %d SYN scan-like conns, and %d connect scan-like conns\n", ps.NetworkFlow, synScanConns, connectScanConns)
	//fmt.Printf("Classifying scan %s as %v\n", ps.NetworkFlow, ps.Type)

}

// determinePortScanTime WILL DETERMINE THE time.Time START AND END TIMES OF THE SCAN,
// IT WILL ALSO DETERMINE THE time.Duration DURATION OF THE SCAN
func (ps *PortScan) determinePortScanTime() {

	// FINDING START AND END TIME OF EACH STREAM IS ACTUALLY AMORTIZED IN THE TCPStream STRUCT
	// THEREFORE, WE ONLY NEED TO LOOK AT START AND END TIMES FOR EACH STREAM AND THEN CALCULATE A DURATION

	for _, stream := range ps.streams {

		// IF TIME IS UNINITIALIZED, THEN INITIALIZE IT TO THE VALUES OF THE FIRST STREAM
		if ps.StartTime.IsZero() && ps.EndTime.IsZero() {
			ps.StartTime = stream.StartTime
			ps.EndTime = stream.EndTime
		} else {

			// IF EITHER STREAM START IS BEFORE THE PORT SCAN'S START, UPDATE THE PORT SCAN'S START
			if stream.StartTime.Before(ps.StartTime) {
				ps.StartTime = stream.StartTime
			}
			if stream.EndTime.Before(ps.StartTime) {
				ps.StartTime = stream.EndTime
			}

			// IF EITHER STREAM START IS AFTER THE PORT SCAN'S END, UPDATE THE PORT SCAN'S END
			if stream.EndTime.After(ps.EndTime) {
				ps.EndTime = stream.EndTime
			}
			if stream.StartTime.After(ps.EndTime) {
				ps.EndTime = stream.StartTime
			}
		}

		// UPDATE THE DURATION OF THE Port Scan
		ps.Duration = stream.EndTime.Sub(stream.StartTime)
	}
}

// NewPortScan CONSTRUCTS A PortScan OBJECT FROM A LIST OF TCP STREAMS AND RETURNS A POINTER
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
		StartTime:     time.Time{},
		EndTime:       time.Time{},
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
	ps.determinePortScanTime()

	// RETURN THE PortScan
	return &ps

}
