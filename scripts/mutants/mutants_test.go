package main

import "testing"

// TestEveryMutantApplies keeps the list in step with the code: an edit whose
// old string no longer occurs exactly once fails here, in go test ./..., and
// not at the next run of the harness.
func TestEveryMutantApplies(t *testing.T) {
	if err := validate(Mutants, Layers(options{})); err != nil {
		t.Fatal(err)
	}
	if err := checkEdits("../..", Mutants); err != nil {
		t.Fatal(err)
	}
}
