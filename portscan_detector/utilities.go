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