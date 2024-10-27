package SSHUtil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func EncryptText(secret, value string) (string, error) {
	block, error := aes.NewCipher([]byte(secret))
	if error != nil {
		return "", error
	}
	plain_text := []byte(value)
	ciphertext := make([]byte, aes.BlockSize+len(plain_text))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plain_text)

	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

func EncryptTextV2(secret, value string) (string, error) {
	block, error := aes.NewCipher([]byte(secret))
	if error != nil {
		return "", error
	}

	var plainTextBlock []byte
	length := len(value)

	if length%16 != 0 {
		extendBlock := 16 - (length % 16)
		plainTextBlock = make([]byte, length+extendBlock)
		copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		plainTextBlock = make([]byte, length)
	}

	copy(plainTextBlock, value)

	ciphertext := make([]byte, len(plainTextBlock))

	iv := "my16digitIvKey12"

	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(ciphertext)

	return str, nil
}

func Decrypt(secret, value string) (string, error) {

	ciphertext, err := base64.RawStdEncoding.DecodeString(value)

	if err != nil {
		return "", fmt.Errorf("decoding base64: %w", err)
	}

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
