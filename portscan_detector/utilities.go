package portscan_detector

import (
	. "github.com/k-mistele/pcap_portscan_detector/set"
)
// contains DETERMINES IF A STRING SLICE CONTAINS A VALUE
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

// mapKeys RETURNS A POINTER TO A SLICE OF KEYS FROM A MAP
func mapKeys(m *map[string] *Set) *[]string {

	var keys []string

	for key := range *m {
		keys = append(keys, key)
	}

	return &keys
}

func formatPortList(s *Set) *string {

	// GET LIST OF INTERFACE FROM THE SET
	items := s.Items()

	// CONVERT TO A LIST OF STRINGS, O(N)
	portStrs := make([]string, len(items))
	for i := range items {
		portStrs[i] = items[i].(string)
	}

	str := ""

	// BUILD A STRING
	for i := range items {
		str += (items[i]).(string) + " "
	}

	return &str
	
}