package lib

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	N *big.Int
	D *big.Int
	P *big.Int
	Q *big.Int
}

func GeneratePrimes() (*big.Int, *big.Int, error) {
	p, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	var q *big.Int

	for {
		q, err = rand.Prime(rand.Reader, 1024)
		if err != nil {
			return nil, nil, err
		}

		if p.Cmp(q) != 0 {
			break
		}
	}

	return p, q, nil
}

func GCD(a, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, a, b)
}

func LCM(a, b *big.Int) *big.Int {
	gcd := GCD(a, b)

	product := new(big.Int).Mul(a, b)

	return product.Div(product, gcd)
}

func Carmichael(p, q *big.Int) *big.Int {
	one := big.NewInt(1)

	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)

	return LCM(pm1, qm1)
}

func GenerateKeys() (*PublicKey, *PrivateKey, error) {
	p, q, err := GeneratePrimes()
	if err != nil {
		return nil, nil, err
	}

	n := new(big.Int).Mul(p, q)

	lambda := Carmichael(p, q)

	e := big.NewInt(65537)

	if GCD(e, lambda).Cmp(big.NewInt(1)) != 0 {
		return nil, nil, errors.New("invalid exponent")
	}

	d := new(big.Int).ModInverse(e, lambda)
	if d == nil {
		return nil, nil, errors.New("modular inverse does not exist")
	}

	publicKey := &PublicKey{
		N: n,
		E: new(big.Int).Set(e),
	}

	privateKey := &PrivateKey{
		N: new(big.Int).Set(n),
		D: d,
		P: p,
		Q: q,
	}

	return publicKey, privateKey, nil
}

func Encrypt(message, e, n *big.Int) (*big.Int, error) {
	if message.Sign() < 0 || message.Cmp(n) >= 0 {
		return nil, errors.New("message must be between 0 and n-1")
	}

	return new(big.Int).Exp(message, e, n), nil
}

func Decrypt(ciphertext, d, n *big.Int) (*big.Int, error) {
	if ciphertext.Sign() < 0 || ciphertext.Cmp(n) >= 0 {
		return nil, errors.New("ciphertext must be between 0 and n-1")
	}

	return new(big.Int).Exp(ciphertext, d, n), nil
}
