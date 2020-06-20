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

func Decrypt(key crypto.PrivateKey, data []byte) (decrypted []byte, err error) {
	if len(data) < 82 {
		err = errors.New("invalid data size")
		return
	}
	private := key.(*PrivateKey)
	if private == nil {
		err = errors.New("invalid private key")
		return
	}
	curve, buf := elliptic.P256(), bytes.Buffer{}
	x, y := elliptic.Unmarshal(curve, data[0:65])
	sym, _ := curve.ScalarMult(x, y, private.D)
	_, err = buf.Write(sym.Bytes())
	if err != nil {
		return
	}
	_, err = buf.Write([]byte{0x00, 0x00, 0x00, 0x01})
	if err != nil {
		return
	}
	_, err = buf.Write(data[0:65])
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
	decrypted, err = ch.Open(nil, hashed[16:], data[65:], nil)
	return
}
