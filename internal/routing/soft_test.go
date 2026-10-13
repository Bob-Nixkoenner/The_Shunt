package routing

import (
	"errors"
	"testing"
)

func TestSplit(t *testing.T) {
	hardE, softE := errors.New("unreachable route"), &SoftError{errors.New("gateway not reachable")}
	hard, soft := Split(errors.Join(errors.Join(nil, softE), hardE))
	if !errors.Is(hard, hardE) || len(soft) != 1 {
		t.Fatalf("hard %v soft %v", hard, soft)
	}
	if hard, soft := Split(errors.Join(softE)); hard != nil || len(soft) != 1 {
		t.Fatalf("only soft: hard %v soft %v", hard, soft)
	}
	if hard, soft := Split(nil); hard != nil || soft != nil {
		t.Fatal("nil")
	}
}
