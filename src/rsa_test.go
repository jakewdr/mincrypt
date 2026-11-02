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

	assert.Equal(t, p.BitLen(), 2048, "p should be 2048 bits")
	assert.Equal(t, q.BitLen(), 2048, "q should be 2048 bits")
	assert.True(t, p.ProbablyPrime(20), true, "p should be prime")
	assert.True(t, q.ProbablyPrime(20), true, "q should be prime")

}

func TestRsaEncrypt(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		m int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RsaEncrypt(tt.m)
		})
	}
}
