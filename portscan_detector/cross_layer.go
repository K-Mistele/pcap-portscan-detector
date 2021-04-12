package portscan_detector

import (
	"fmt"
)

// CrossLayerFlow IS A TYPE THAT REPRESENTS A SOCKET CONNECTION - A TWO-TUPLE OF TWO-TUPLES
// CrossLayerFlow IS DESIGNED TO BE USED AS A MAP KEY SINCE IT SHOULD BE HASHABLE
type CrossLayerFlow struct {

	SrcHost		string
	SrcPort		string
	DstHost		string
	DstPort		string
	Repr 		string		// A string REPRESENTATION OF THE FLOW

}

// NewCrossLayerFlow RETURNS A POINTER TO A NEW CrossLayerFlow
func NewCrossLayerFlow(srcHost string, srcPort string, dstHost string, dstPort string) *CrossLayerFlow {
	return  &CrossLayerFlow {
		SrcHost: 	srcHost,
		SrcPort: 	srcPort,
		DstHost: 	dstHost,
		DstPort: 	dstPort,
		Repr: 		fmt.Sprintf("%s:%s->%s:%s", srcHost, srcPort, dstHost, dstPort),
	}
}
