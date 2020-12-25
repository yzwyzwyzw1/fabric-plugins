/*
Copyright Hyperledger - Technical Working Group China. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package sw

import (
	"errors"
	"github.com/Hyperledger-TWGC/ccs-gm/sm3"
	"github.com/hyperledger/fabric/bccsp"
)


type sm4PrivateKey struct {
	privKey []byte
	exportable bool
}


func (k *sm4PrivateKey) Bytes() (raw []byte,err error) {
	if k.exportable {
		return k.privKey,nil
	}
	return nil,errors.New("Not supported.")
}

func (k *sm4PrivateKey) SKI() (ski []byte) {
	hash := sm3.New()
	hash.Write([]byte{0x01})
	hash.Write(k.privKey)
	return hash.Sum(nil)
}

func (k *sm4PrivateKey) Symmetric() bool {
	return true
}

func (k *sm4PrivateKey) Private() bool {
	return true
}

func (k *sm4PrivateKey) PublicKey() (bccsp.Key,error) {
	return nil,errors.New("Cannot call this method on a sysmetric key.")
}

