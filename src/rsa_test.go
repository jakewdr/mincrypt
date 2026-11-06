package mincrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrimes(t *testing.T) {
	p, q, err := GeneratePrimes()

	if err != nil {
		t.Fatalf("GeneratePrimes() returned an error: %v", err)
	}

	if p == nil || q == nil {
		t.Fatal("Expected two big ints, got nil")
	}

	assert.Equal(t, p.BitLen(), 1024, "p should be 1024 bits")
	assert.Equal(t, q.BitLen(), 1024, "q should be 1024 bits")
	assert.True(t, p.ProbablyPrime(20), true, "p should be prime")
	assert.True(t, q.ProbablyPrime(20), true, "q should be prime")

}
