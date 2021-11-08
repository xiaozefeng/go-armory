package rsautil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func SignPKCS1v15(content []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(content)
	sign, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func VerifyPKCS1v15(content, sign []byte, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256(content)
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], sign)
}

func PrivateKeyToBytes(privateKey *rsa.PrivateKey) []byte {
	priBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	return priBytes
}

func PublicKeyToBytes(publicKey *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubBytes, nil
}

func BytesToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	enc := x509.IsEncryptedPEMBlock(block)
	var b = block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func BytesToPublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	enc := x509.IsEncryptedPEMBlock(block)
	var b = block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	key, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	publickey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parse pkix publickey failed")
	}
	return publickey, nil
}

// ciphertext
func EncryptWithPublicKey(content []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, content, nil)
}

// plaintext
func DecryptWithPrivateKey(ciphertext []byte, pri *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptOAEP(sha512.New(), rand.Reader, pri, ciphertext, nil)
}
