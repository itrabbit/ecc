package ecc

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func (key PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(key.D)
}

func (key PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(elliptic.Marshal(key.Curve, key.X, key.Y))
}

func PublicKeyFromString(public string) (*PublicKey, error) {
	publicKey, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, publicKey)
	if x == nil || y == nil {
		return nil, errors.New("invalid public key")
	}
	return &PublicKey{
		Curve: curve,
		X:     x, Y: y,
	}, nil
}

func KeyFromString(private string) (*PrivateKey, error) {
	d, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(d)
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x, Y: y,
		},
		D: d,
	}, nil
}

func GenerateKey() (*PrivateKey, error) {
	curve := elliptic.P256()
	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}, nil
}
