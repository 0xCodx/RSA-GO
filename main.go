package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func genRsaKey(size int) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	privateKey, _ = rsa.GenerateKey(rand.Reader, size)
	publicKey = &privateKey.PublicKey
	return
}

//key to pem
func KeyToPem(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) (privMem string, pubMem string) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	privPEM := string(privPEMBytes)

	PubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return
	}
	PubPEMBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: PubKeyBytes,
		},
	)
	pubPEM := string(PubPEMBytes)
	return privPEM, pubPEM
}

//pem to file
func WriteToFile(x []byte, filename string) (err error) {
	filepath := fmt.Sprintf("%s", filename)
	_ = ioutil.WriteFile(filepath, x, 0644)
	return
}

func main() {

	pv, pb := genRsaKey(5000)

	pvPem, pbPem := KeyToPem(pv, pb)

	WriteToFile([]byte(pvPem), "private.pem")
	WriteToFile([]byte(pbPem), "public.pem")
}
