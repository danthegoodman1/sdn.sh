//go:build linux

package linux

import (
	"slices"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/kernel"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// TestAnEgressGrantSurvivesItsAlias checks that a link's grant reads back
// from the alias it is recorded in, including the class a deny leaves.
func TestAnEgressGrantSurvivesItsAlias(t *testing.T) {
	rules := []kernel.EgressRule{
		{Proto: model.TCP, Ports: model.PortRange{Lo: 1, Hi: 24}},
		{Proto: model.TCP, Ports: model.PortRange{Lo: 26, Hi: 65535}},
		{Proto: model.UDP},
		{Proto: model.OtherProto},
	}
	got, err := parseRules(formatRules(rules))
	if err != nil || !slices.Equal(got, rules) {
		t.Fatalf("read back %+v, %v; want %+v", got, err, rules)
	}
}
