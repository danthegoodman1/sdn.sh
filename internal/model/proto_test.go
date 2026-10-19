package model

import "testing"

func TestAGrantMatchesItsProtocolsAndPorts(t *testing.T) {
	for _, c := range []struct {
		grant Proto
		ports PortRange
		proto Proto
		port  uint16
		want  bool
	}{
		{OtherProto, PortRange{}, TCP, 80, false},
		{OtherProto, PortRange{}, UDP, 53, false},
		{OtherProto, PortRange{}, "icmp", 0, true},
		{AnyProto, PortRange{}, "icmp", 0, true},
		{AnyProto, PortRange{}, TCP, 22, true},
		{TCP, PortRange{Lo: 80, Hi: 90}, TCP, 85, true},
		{TCP, PortRange{Lo: 80, Hi: 90}, TCP, 91, false},
		{TCP, PortRange{Lo: 80, Hi: 90}, UDP, 85, false},
		{UDP, PortRange{}, UDP, 9, true},
	} {
		if got := c.grant.Matches(c.ports, c.proto, c.port); got != c.want {
			t.Errorf("%s/%s admits %s/%d: %v, want %v", c.grant, c.ports, c.proto, c.port, got, c.want)
		}
	}
}
