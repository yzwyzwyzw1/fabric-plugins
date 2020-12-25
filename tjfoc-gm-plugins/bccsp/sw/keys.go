/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"encoding/pem"
	"errors"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm4"
	gmX509 "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
)



//--------------------------------------------------------//
// PublicKeyToDER marshals a public key to the der format
func publicKeyToDER(publicKey *sm2.PublicKey) ([]byte, error) {

	if publicKey == nil{
		return nil,errors.New("Invalid public Key. It must be different from nil.")
	}
	PubASN1, err := gmX509.MarshalSm2PublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return PubASN1, nil
}

// DERToPublicKey unmarshals a der to public key
func derToPublicKey(raw []byte) (pub *sm2.PublicKey, err error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid DER. It must be different from nil.")
	}

	key, err := gmX509.ParseSm2PublicKey(raw)

	return key, err
}

// DERToPrivateKey unmarshals a der to private key
func derToPrivateKey(der []byte) (key *sm2.PrivateKey, err error) {

	key,err=gmX509.ParsePKCS8PrivateKey(der,nil)
	if err == nil{
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an sm2.PrivateKey")
}



func privateKeyToDER(privateKey *sm2.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid sm2 private key. It must be different from nil")
	}

	return gmX509.MarshalSm2PrivateKey(privateKey,nil)
	return gmX509.MarshalSm2EcryptedPrivateKey(privateKey,nil)
}

func privateKeyToPEM(privateKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {


	if privateKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}

	return gmX509.WritePrivateKeyToPem(privateKey, pwd)

}
func privateKeyToEncryptedPEM(privateKey *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("invalid private key. It must be different from nil")
	}

	return gmX509.MarshalSm2EcryptedPrivateKey(privateKey,pwd)
}
func pemToPrivateKey(raw []byte, pwd []byte) (*sm2.PrivateKey, error) {

	//priv,err :=gmX509.ReadPrivateKeyFromMem(raw,pwd)
	priv,err :=gmX509.ReadPrivateKeyFromPem(raw,pwd)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return priv,nil
}

func publicKeyToPEM(publicKey *sm2.PublicKey, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return gmX509.WritePublicKeyToPem(publicKey)
}

func publicKeyToEncryptedPEM(publicKey *sm2.PublicKey, pwd []byte) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return gmX509.WritePublicKeyToPem(publicKey)
}





func pemToPublicKey(raw []byte, pwd []byte) (*sm2.PublicKey, error) {

	pub,err := gmX509.ReadPublicKeyFromPem(raw)
	if err !=nil {
		return nil, errors.New("error pem,can not read private key from pem")
	}
	return pub,nil

}



// ------------------------------------------- //
func sm4ToPEM(raw []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "SM4 KEY", Bytes: raw})
}

// PEMtoAES extracts from the PEM an SM4 key
func pemToSM4(raw []byte, pwd []byte) ([]byte, error) {

	//sm4key,err := sm4.ReadKeyFromMem(raw,pwd)
	sm4key,err := sm4.ReadKeyFromPem(raw,pwd)

	if err != nil {
		return nil, errors.New("Invalid key. It must be different from nil.")
	}
	return sm4key,nil
}


// SM4toEncryptedPEM encapsulates an SM4 key in the encrypted PEM format
func sm4ToEncryptedPEM(raw []byte, pwd []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, errors.New("Invalid aes key. It must be different from nil")
	}

	//return sm4.WriteKeytoMem(raw,pwd)
	return sm4.WriteKeyToPem(raw,pwd)


}