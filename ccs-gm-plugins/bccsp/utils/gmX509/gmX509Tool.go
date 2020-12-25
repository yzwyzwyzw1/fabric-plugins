package gmX509

import (

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/utils"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
)

func MarshalPKISM2PublicKey(key *sm2.PublicKey)([]byte,error){
	return x509.MarshalPKIXPublicKey(key)
}

func MarshalPKISM2PrivateKey(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return x509.MarshalECPrivateKey(key)
}

func WritePrivateKeytoMem(key *sm2.PrivateKey, pwd []byte) ([]byte, error) {
	return utils.PrivateKeyToPEM(key,pwd)
}

func WritePublicKeytoMem(key *sm2.PublicKey,pwd []byte) ([]byte, error) {
	return utils.PublicKeyToPEM(key,pwd)
}

func ParsePKISM2PublicKey(der []byte) (*sm2.PublicKey, error) {
	key,err:=x509.ParsePKIXPublicKey(der)
	if err != nil{
		return nil, err
	}
	return key.(*sm2.PublicKey),err
}

func MarshalECSM2PrivateKey(key *sm2.PrivateKey,pwd []byte) ([]byte, error) {
	return x509.MarshalECPrivateKey(key)
}

func ReadPrivateKeyFromMem(data []byte, pwd []byte) (*sm2.PrivateKey, error) {
	return utils.PEMtoPrivateKey(data,pwd)
}

func ReadPublicKeyFromMem(data []byte, pwd []byte) (*sm2.PublicKey, error) {
	return utils.PEMtoPublicKey(data,pwd)
}

func DerToPrivateKey(der []byte)(*sm2.PrivateKey,error){
	//key,err:=x509.ParsePKCS8PrivateKey(der)
	key,err:=x509.ParseECPrivateKey(der)
	if err != nil{
		return nil, err
	}
	return key.(*sm2.PrivateKey),err
}