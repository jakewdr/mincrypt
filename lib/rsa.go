package lib

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"

	"lukechampine.com/blake3"
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

func Mgf1(seed []byte, length uint64) ([]byte, error) {
	// 137438953472 is 32 << 32, blake3 hashes have a length of 32
	if (length > uint64(137438953472)) || (length == 0) {
		return nil, errors.New("mask is of incorrect length")
	}

	T := make([]byte, 0, length)

	var iterations uint32 = 0
	var C [4]byte

	// Until the number of bytes needed have been appended
	for len(T) < int(length) {
		binary.BigEndian.PutUint32(C[:], iterations)
		h := blake3.New(32, nil)
		_, _ = h.Write(seed) // Discard unlikely return values (underscores)
		_, _ = h.Write(C[:])
		T = append(T, h.Sum(nil)...) // Outputs to open buffer
		iterations++
	}

	return T[:length], nil // Returns the first bytes of length or error
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
