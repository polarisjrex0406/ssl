package utils

import (
	"net"
	"strings"
)

func LoadIPs(ipList string) []string {
	ips := strings.Split(ipList, ",")
	var validIPs []string
	// Validate each IP
	for _, ipStr := range ips {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip == nil {
			continue
		}
		validIPs = append(validIPs, ipStr)
	}

	return validIPs
}
