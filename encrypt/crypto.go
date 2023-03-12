package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

func encryptStream(key string, initVector []byte) (cipher.Stream, error) {

	block, err := makeCipherBlock(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewCFBEncrypter(block, initVector), nil

}
func Encrypt(key, plaintext string) (string, error) {

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	initVector := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, initVector); err != nil {
		return "", err
	}
	stream, err := encryptStream(key, initVector)
	if err != nil {
		return "", err
	}
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return fmt.Sprintf("%x", ciphertext), nil
}

func EncryptWriter(key string, w io.Writer) (*cipher.StreamWriter, error) {
	initVector := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, initVector); err != nil {
		return nil, err
	}

	stream, err := encryptStream(key, initVector)
	if err != nil {
		return nil, err
	}

	bn, err := w.Write(initVector)
	if bn != len(initVector) {
		return nil, errors.New("crypto: missmatch of init vector bytes written in writer")
	}

	return &cipher.StreamWriter{
		S:   stream,
		W:   w,
		Err: nil,
	}, nil
}

func decryptStream(key string, initVector []byte) (cipher.Stream, error) {

	block, err := makeCipherBlock(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBDecrypter(block, initVector)

	return stream, nil
}

func Decrypt(key, crypted string) (string, error) {
	ciphertext, err := hex.DecodeString(crypted)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("crypto: cipher hex is too short, no way to decrypt it.")
	}

	initVector := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream, err := decryptStream(key, initVector)
	if err != nil {
		return "", err
	}
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}

func DecryptReader(key string, r io.Reader) (*cipher.StreamReader, error) {
	initVector := make([]byte, aes.BlockSize)
	bn, err := r.Read(initVector)
	if bn < len(initVector) || err != nil {
		return nil, errors.New("crypto: missmatch of init vector bytes read from reader")
	}
	stream, err := decryptStream(key, initVector)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{
		S: stream,
		R: r,
	}, nil
}

func makeCipherBlock(key string) (cipher.Block, error) {
	hashHash := md5.New()
	fmt.Fprint(hashHash, key)
	cipherKey := hashHash.Sum(nil)
	return aes.NewCipher(cipherKey)
}
