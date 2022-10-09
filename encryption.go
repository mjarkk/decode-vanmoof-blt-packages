package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

var aesCbcKey []byte

func setupCrypto(bikeKey string) {
	key, err := hex.DecodeString(bikeKey)
	if err != nil {
		fatal(err.Error())
	}
	if len(key) != 16 {
		fatal("bikeKey must be a 32 hex character string (16 bytes)")
	}
	aesCbcKey = key
}

func canDecrypt() bool {
	return aesCbcKey != nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesCbcKey)
	if err != nil {
		return nil, err
	}

	const blockSize = 16
	iv := [blockSize]byte{}

	blockAlignment := len(ciphertext) % blockSize
	if blockAlignment != 0 {
		ciphertext = append(ciphertext, bytes.Repeat([]byte{0}, blockSize-blockAlignment)...)
	}

	cbc := cipher.NewCBCDecrypter(block, iv[:])
	cbc.CryptBlocks(ciphertext, ciphertext)

	for i := len(ciphertext) - 1; i >= 0; i-- {
		if ciphertext[i] != 0 {
			return ciphertext[:i+1], nil
		}
	}

	return []byte{}, nil
}
