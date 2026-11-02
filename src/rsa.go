package mincrypt

import (
	"crypto/rand"
	"math/big"
)

func GeneratePrimes() (*big.Int, *big.Int, error) {
	p, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	q, err := rand.Prime(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	return p, q, nil
}

func RsaEncrypt(m int) {
	p, q, err := GeneratePrimes()

	if err != nil {
		panic(err)
	}

	var n = new(big.Int)
	n = n.Mul(p, q)

}
