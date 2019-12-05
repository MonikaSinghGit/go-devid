// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	
	"crypto/ecdsa"
	//"crypto/rsa"
	//"crypto/dsa"
	//"crypto/aes"
    //"crypto/cipher"
    
	//"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

)

func decodeAlgorithm(code x509.PublicKeyAlgorithm) string {
    var s string
    switch code {
    case x509.RSA:
            s = "RSA"
    case x509.DSA:
            s = "DSA"
    case x509.ECDSA:
            s = "ECDSA"
    default:
            s = "oops"
    }
    return s
}

func main(){
	//Public_key_out()

/////////////////////////////////////Signature//////////////////////////////////////////////////////////////
	file := "go/src/SecureDeviceIdentity/certs/DI40.key.pem"
	keyjson, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	//fmt.Println(IsEncryptedPEMBlock(keyjson));

	block, _ := pem.Decode([]byte(keyjson))
	if block == nil {
		panic("failed to parse PEM block containing the public key")
	}
	fmt.Println("Block",block);

	prvt, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	fmt.Println("prvt",prvt);

	msg := "hello, world"
	hash := sha256.Sum256([]byte(msg))

	r, s, err := ecdsa.Sign(rand.Reader, prvt.(*ecdsa.PrivateKey), hash[:])
	if err != nil {
		panic(err)
	}
	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)




/////////////////////////////////////Verification Opertaion//////////////////////////////////////////


certfile := "go/src/SecureDeviceIdentity/certs/DI40.cert.pem"
certjson, err := ioutil.ReadFile(certfile)
	if err != nil {
		panic(err)
	}

certblock, _ := pem.Decode([]byte(certjson))
	if certblock == nil {
		panic("failed to parse certificate PEM")
	}
	//var cert *ecdsa.Certificate
	cert, err := x509.ParseCertificate(certblock.Bytes)
	//pub, err:=x509.ParsePKIXPublicKey(cert.PublicKey)

	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}


	fmt.Println("Public key algorithm",decodeAlgorithm(cert.PublicKeyAlgorithm))
	
	fmt.Println(cert.Subject)
	fmt.Println(cert.Issuer)
	pub:=cert.PublicKey

	var pp *ecdsa.PublicKey
	pp=pub.(*ecdsa.PublicKey)
	fmt.Println("Public key",pp)
	fmt.Printf("signature: (0x%x, 0x%x)\n", r, s)
	flg:=ecdsa.Verify(pp, hash[:], r, s)

	fmt.Println("flg",flg);

	
}






