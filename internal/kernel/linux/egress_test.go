//go:build linux

package linux

import (
	"testing"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// TestAnEgressRuleReadsBackFromItsRecord checks that each flow of a grant
// reads back from the text its rule records, including the class a deny
// leaves.
func TestAnEgressRuleReadsBackFromItsRecord(t *testing.T) {
	for _, r := range []kernel.EgressRule{
		{Proto: model.TCP, Ports: model.PortRange{Lo: 1, Hi: 24}},
		{Proto: model.TCP, Ports: model.PortRange{Lo: 26, Hi: 65535}},
		{Proto: model.UDP},
		{Proto: model.OtherProto},
		{Proto: model.AnyProto},
	} {
		if got, err := parseRule(formatRule(r)); err != nil || got != r {
			t.Fatalf("read back %+v, %v; want %+v", got, err, r)
		}
	}
}
