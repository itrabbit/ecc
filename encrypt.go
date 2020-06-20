package ecc

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
)

func Encrypt(key crypto.PublicKey, data []byte) (encrypted []byte, err error) {
	if len(data) < 1 {
		err = errors.New("empty data")
		return
	}
	public := key.(*PublicKey)
	if public == nil {
		err = errors.New("invalid public key")
		return
	}
	private, err := GenerateKey()
	if err != nil {
		return
	}
	ephemeral := elliptic.Marshal(private.Curve, private.X, private.Y)
	sym, _ := public.Curve.ScalarMult(public.X, public.Y, private.D)
	// Create buffer
	buf := bytes.Buffer{}
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	hashed := sha256.Sum256(buf.Bytes())
	buf.Reset()
	block, err := aes.NewCipher(hashed[0:16])
	if err != nil {
		return
	}
	ch, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return
	}
	_, err = buf.Write(ephemeral)
	if err != nil {
		return
	}
	_, err = buf.Write(ch.Seal(nil, hashed[16:], data, nil))
	if err != nil {
		return
	}
	encrypted = buf.Bytes()
	return
}
