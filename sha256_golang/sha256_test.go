package sha256_golang

import (
	"regexp"
	"testing"
)

func TestHello(t *testing.T) {
	name := "world"
	want := regexp.MustCompile(`\b` + name + `\b`)
	msg, err := Hello("world")
	if !want.MatchString(msg) || err != nil {
		t.Fatalf(`Hello("world") = %q, %v, want match for %#q, nil`, msg, err, want)
	}
}
