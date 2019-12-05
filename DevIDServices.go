// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"reflect"
	"strings"
	"time"
)

type PubKeystrct struct {
	keyIndex          int
	publicKeyMaterial *ecdsa.PublicKey
	enable            bool
}

type DevIDCredentialstrct struct {
	credentialIndex int
	pubkeyIndex     int
	enable          bool
	credential      *x509.Certificate
}

type DevIDCredentialChainStruct struct {
	credentialChainIndex      int
	credentialChainCredential *x509.Certificate
}

var devIDCredentialTbl []DevIDCredentialstrct

var pblcKeyTbl []PubKeystrct
var DevIDModule string
var chainCredential string
var DevIDSecrets string

func initialization() bool {
	var iniflg bool
	if issExist(DevIDModule) == true {
		if issExist(chainCredential) == true {

			if issExist(DevIDSecrets) == true {

				dvMdl := DevIDModule
				files1, err := ioutil.ReadDir(dvMdl)
				if err != nil {
					log.Fatal(err)
				}
				iniflg = true

				for _, file1 := range files1 {
					cacertfile := dvMdl + file1.Name()
					cacertjson, caerr := ioutil.ReadFile(cacertfile)
					if caerr != nil {
						panic(caerr)
					}
					cacertblock, _ := pem.Decode([]byte(cacertjson))
					if cacertblock == nil {
						panic("failed to parse certificate PEM")
					}
					cacert, caerr := x509.ParseCertificate(cacertblock.Bytes)
					strt := cacert.NotBefore
					end := cacert.NotAfter
					iniflg = NotExpiredCert(strt, end)
					if iniflg == false {
						break
					}
				}

			} else {
				fmt.Println("DevID secret folder not found!!")
				iniflg = false
			}

		} else {
			fmt.Println("Credential chain not found!!")
			iniflg = false
		}

	} else {
		fmt.Println("DevID credential not found!!")
		iniflg = false
	}

	return iniflg

}

func EnumerationOfDevIDPublicKeyTest() [3]*ecdsa.PublicKey {

	dvMdl := DevIDModule
	var pubkeyArr [3]*ecdsa.PublicKey
	files2, err := ioutil.ReadDir(dvMdl)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("range::", len(files2))

	var count int
	count = 0
	var pub *ecdsa.PublicKey

	for _, file2 := range files2 {
		fmt.Println(file2.Name())
		certfile := dvMdl + file2.Name()

		fmt.Println("certfile:", certfile)
		certjson, err := ioutil.ReadFile(certfile)
		if err != nil {
			panic(err)
		}

		certblock, _ := pem.Decode([]byte(certjson))
		if certblock == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(certblock.Bytes)

		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		pp := cert.PublicKey
		pub = pp.(*ecdsa.PublicKey)
		pubkeyArr[0] = pub
		fmt.Println("Public key::::::: ", pub)

		count++

	}

	return pubkeyArr

}

func EnumerationOfDevIDPublicKey() []PubKeystrct {
	dvMdl := DevIDModule
	var tmpIdevIDInx int
	var tmpstr string
	files2, err := ioutil.ReadDir(dvMdl)
	if err != nil {
		log.Fatal(err)
	}

	var sz int
	sz = len(files2)
	var pubkeyArr = make([]PubKeystrct, sz)
	var count int
	count = 0
	var pub *ecdsa.PublicKey

	for _, file2 := range files2 {
		tmpstr = file2.Name()

		if tmpstr[:6] == "IDevID" {
			tmpIdevIDInx = count

		}

		certfile := dvMdl + file2.Name()
		certjson, err := ioutil.ReadFile(certfile)
		if err != nil {
			panic(err)
		}

		certblock, _ := pem.Decode([]byte(certjson))
		if certblock == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(certblock.Bytes)

		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}

		pp := cert.PublicKey
		pub = pp.(*ecdsa.PublicKey)
		pubkeyArr[count].keyIndex = count
		pubkeyArr[count].publicKeyMaterial = pub
		pubkeyArr[count].enable = true

		count++
	}

	/****************************************Swaping IDevId on index 0*********************************************************************/
	var tmpArr PubKeystrct
	var tmpindx int

	tmpArr = pubkeyArr[0]
	pubkeyArr[0] = pubkeyArr[tmpIdevIDInx]
	tmpindx = pubkeyArr[0].keyIndex
	pubkeyArr[0].keyIndex = 0
	tmpArr.keyIndex = tmpindx
	pubkeyArr[tmpIdevIDInx] = tmpArr

	return pubkeyArr

}

func EnumerationOfDevIDCredentials() []DevIDCredentialstrct {

	dvMdl2 := DevIDModule
	var tmpIdevIDInx int
	var keyIndx int

	var tmpstr string
	files2, err := ioutil.ReadDir(dvMdl2)
	if err != nil {
		log.Fatal(err)
	}
	var sz int
	sz = len(files2)
	var crdntlArr = make([]DevIDCredentialstrct, sz)
	var count int
	count = 0
	var pub *ecdsa.PublicKey

	for _, file2 := range files2 {
		tmpstr = file2.Name()
		if tmpstr[:6] == "IDevID" {
			tmpIdevIDInx = count
		}
		certfile := dvMdl2 + file2.Name()
		certjson, err := ioutil.ReadFile(certfile)
		if err != nil {
			panic(err)
		}
		certblock, _ := pem.Decode([]byte(certjson))
		if certblock == nil {
			panic("failed to parse certificate PEM")
		}
		cert, err := x509.ParseCertificate(certblock.Bytes)
		pp := cert.PublicKey
		pub = pp.(*ecdsa.PublicKey)
		var pub1 *ecdsa.PublicKey
		var pub2 *ecdsa.PublicKey
		for i := 0; i < len(pblcKeyTbl); i++ {
			pub1 = pub
			if pblcKeyTbl[i].publicKeyMaterial == nil {
				pblcKeyTbl = EnumerationOfDevIDPublicKey()
			} else {
				pub2 = pblcKeyTbl[i].publicKeyMaterial
				if pub1.X.Cmp(pub2.X) == 0 && pub1.Y.Cmp(pub2.Y) == 0 {
					keyIndx = pblcKeyTbl[i].keyIndex
					break
				}
			}
		}

		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}
		crdntlArr[count].credentialIndex = count
		crdntlArr[count].pubkeyIndex = keyIndx
		crdntlArr[count].enable = true
		crdntlArr[count].credential = cert

		count++
	}

	var tmpArr DevIDCredentialstrct
	var tmpindx int
	tmpArr = crdntlArr[0]
	crdntlArr[0] = crdntlArr[tmpIdevIDInx]
	tmpindx = crdntlArr[0].credentialIndex
	crdntlArr[0].credentialIndex = 0
	tmpArr.credentialIndex = tmpindx
	crdntlArr[tmpIdevIDInx] = tmpArr

	return crdntlArr

}

func EnumerationOfDevIDCredentialChain(credentialIndex int) []DevIDCredentialChainStruct {

	fmt.Println("credentialIndex:", credentialIndex)

	var tmpCert *x509.Certificate
	if devIDCredentialTbl[credentialIndex].credential == nil {
		devIDCredentialTbl = EnumerationOfDevIDCredentials()
	}
	tmpCert = devIDCredentialTbl[credentialIndex].credential

	files2, err := ioutil.ReadDir(chainCredential)
	if err != nil {
		log.Fatal(err)
	}

	var certBlocksArray []DevIDCredentialChainStruct
	var count int
	count = 0
	var cbindx int

	for _, file2 := range files2 {
		certBlocksArray = make([]DevIDCredentialChainStruct, 1)
		certfile := chainCredential + file2.Name()
		certjson, err := ioutil.ReadFile(certfile)
		if err != nil {
			panic(err)
		}
		rest := certjson
		cbindx = 0
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				fmt.Printf("Error: PEM not parsed\n")
				break
			}
			if cbindx == 0 {

				certBlocksArray[cbindx].credentialChainIndex = cbindx
				certBlocksArray[cbindx].credentialChainCredential, _ = x509.ParseCertificate([]byte(block.Bytes))
				if err != nil {
					fmt.Printf("Error: %s\n", err)
				}
			} else {

				var secondcrt DevIDCredentialChainStruct
				secondcrt.credentialChainIndex = cbindx
				secondcrt.credentialChainCredential, _ = x509.ParseCertificate([]byte(block.Bytes))
				if err != nil {
					fmt.Printf("Error: %s\n", err)
				}
				certBlocksArray = append(certBlocksArray, secondcrt)
			}
			cbindx++
			if len(rest) == 0 {
				break
			}
		}
		var tmpchainCert *x509.Certificate
		tmpchainCert = certBlocksArray[0].credentialChainCredential

		if reflect.DeepEqual(tmpCert.AuthorityKeyId, tmpchainCert.SubjectKeyId) {
			break
		} else {
			certBlocksArray = nil
		}
		count++
	}
	return certBlocksArray

}

func Signing(keyIndex int, currentEncoding string, dataLength int, dataOctets string) (bool, *big.Int, *big.Int) {

	var flg bool
	var r, s *big.Int
	r = nil
	s = nil
	flg = false
	if currentEncoding == "ECDSADIGESTINFO_OPAQUE" {
		if pblcKeyTbl[keyIndex].enable == true {
			pub := pblcKeyTbl[keyIndex].publicKeyMaterial
			files, err := ioutil.ReadDir(DevIDSecrets)
			if err != nil {
				log.Fatal(err)
			}

			for _, file := range files {
				prvtfile := DevIDSecrets + file.Name()
				keyjson, err := ioutil.ReadFile(prvtfile)
				if err != nil {
					panic(err)
				}
				prvtKey, _ := pem.Decode([]byte(keyjson))
				if prvtKey == nil {
					panic("failed to parse PEM block containing the public key")
				}
				prvt, err := x509.ParsePKCS8PrivateKey(prvtKey.Bytes)
				prvtPub := prvt.(*ecdsa.PrivateKey).Public()
				var pub1 *ecdsa.PublicKey
				var pub2 *ecdsa.PublicKey
				pub1 = pub
				pub2 = prvtPub.(*ecdsa.PublicKey)
				if pub1.X.Cmp(pub2.X) == 0 && pub1.Y.Cmp(pub2.Y) == 0 {
					msg := dataOctets
					hash := sha256.Sum256([]byte(msg))
					r, s, err := ecdsa.Sign(rand.Reader, prvt.(*ecdsa.PrivateKey), hash[:])
					if err != nil {
						panic(err)
					}
					flg = true
					return flg, r, s
				}

			}

			if flg == false {
				fmt.Println("Private key not found!!")
			}

		} else {
			fmt.Println("Public key is not enabled!!")
			return flg, r, s
		}

	} else {
		fmt.Println("This operation supports only ECC key")
		return flg, r, s
	}
	return flg, r, s
}

func DevIDCredentialEnable(credentialIndex int) bool {

	var creflg bool
	if devIDCredentialTbl[credentialIndex].credential == nil {
		fmt.Println("DevID credential not enumerated!! Please perform operation 3 first!")
		creflg = false
	} else {
		devIDCredentialTbl[credentialIndex].enable = true
		if devIDCredentialTbl[credentialIndex].enable == true {
			creflg = true
		} else {
			creflg = false
		}

	}
	return creflg
}

func DevIDCredentialDisable(credentialIndex int) bool {
	var credflg bool
	if devIDCredentialTbl[credentialIndex].credential == nil {
		fmt.Println("DevID credential not enumerated!! Please perform operation 3 first!")
		credflg = false
	} else {
		devIDCredentialTbl[credentialIndex].enable = false
		if devIDCredentialTbl[credentialIndex].enable == false {
			credflg = true
		} else {
			credflg = false
		}
	}
	return credflg
}
func DevIDKeyEnable(keyIndex int) bool {
	var keyflg bool
	if pblcKeyTbl[keyIndex].publicKeyMaterial == nil {
		fmt.Println("DevID Public key not enumerated!! Please perform operation 2 first!")
	} else {

		pblcKeyTbl[keyIndex].enable = true
		if pblcKeyTbl[keyIndex].enable == true {
			keyflg = true
		} else {
			keyflg = false
		}

	}
	return keyflg
}

func DevIDKeyDisable(keyIndex int) bool {

	var keydflg bool
	if pblcKeyTbl[keyIndex].publicKeyMaterial == nil {
		fmt.Println("DevID Public key not enumerated!! Please perform operation 2 first!")
	} else {
		pblcKeyTbl[keyIndex].enable = false
		if pblcKeyTbl[keyIndex].enable == false {
			keydflg = true
		} else {
			keydflg = false
		}

	}
	return keydflg
}

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

func TimeToDays(t time.Time) int {
	return int(math.Round(time.Since(t).Hours() / 24))
}

func NotExpiredCert(NotBefore time.Time, NotAfter time.Time) bool {

	nb := TimeToDays(NotBefore)
	na := -TimeToDays(NotAfter)
	if (nb >= 0) || (na >= nb) {
		return true
	} else {
		return false
	}

}

func numberofDevID(dvMdl string) int {
	files1, err := ioutil.ReadDir(dvMdl)
	if err != nil {
		log.Fatal(err)
	}
	return len(files1)

}

func issExist(mdl string) bool {
	var exstflg bool
	if _, err := os.Stat(mdl); err != nil {
		if os.IsNotExist(err) {
			exstflg = false
		} else {
			exstflg = true
		}

	} else {
		exstflg = true
	}
	return exstflg
}

func main() {
	cnfgFile, cfgerr := ioutil.ReadFile("config.cfg")

	if cfgerr != nil {
		log.Fatal(cfgerr)
	}
	cfgstr := string(cnfgFile[:])
	DevIDLocation := strings.Split(cfgstr, "DevIDLocation=")
	certFldr:=strings.TrimSpace(DevIDLocation[1])

	fmt.Print("Enter the DevID Module: ")
	var DevID string
	fmt.Scanln(&DevID)
	fmt.Print(certFldr+"+++++++++++++++"+DevID)
	exst1 := issExist(certFldr+DevID)

	if exst1 == false {
		fmt.Println("DevID module not found!!!")
	} else {

		DevIDModule = certFldr + DevID + "/DevIDCredentials/"
		chainCredential = certFldr + DevID + "/CredentialChain/"
		DevIDSecrets = certFldr + DevID + "/DevIDSecrets/"

		var inpt int
		var fg bool
		var numOfDevIDs int
		numOfDevIDs = numberofDevID(DevIDModule)
		pblcKeyTbl = make([]PubKeystrct, numOfDevIDs)
		devIDCredentialTbl = make([]DevIDCredentialstrct, numOfDevIDs)
		var signR, signS *big.Int

		for inpt != 10 {
			fmt.Println("Select the operation:\n 1. for Initialization\t\t\t2. for Enumeration of DevID Public Key\t\t3. for Enumeration of DevID credential\t\t4. for Enumeration of a DevID credential chain\t\t 5. for singing\n 6. for Enabling DevID Credential\t7. for Disable DevID Credential\t\t\t8. for Enabling DevID key\t\t\t9. for Disable DevID key\t\t\t\t10. for exit\n")
			fmt.Scanln(&inpt)

			switch inpt {
			case 1:
				fmt.Println("*******************************************************************Intialization***********************************************************************************************************************")
				fg = initialization()
				fmt.Println(" Intialization: ", fg, "\n")

			case 2:

				if pblcKeyTbl[0].publicKeyMaterial == nil {
					pblcKeyTbl = EnumerationOfDevIDPublicKey()
				}
				fmt.Println("*******************************************************************Enumeration of DevID Public key***************************************************************************************************************************\n")
				fmt.Println("KeyIndex | Status |  Key Material")
				for i := 0; i < len(pblcKeyTbl); i++ {
					fmt.Println("  ", pblcKeyTbl[i].keyIndex, "    | ", pblcKeyTbl[i].enable, " | ", pblcKeyTbl[i].publicKeyMaterial)
				}

				fmt.Println("\n")

			case 3:
				if devIDCredentialTbl[0].credential == nil {
					devIDCredentialTbl = EnumerationOfDevIDCredentials()
				}
				fmt.Println("*******************************************************************DevID Credentials***************************************************************************************************************************")
				fmt.Println("CredentialIndex | KeyIndex | Status |  Credential")
				for i := 0; i < len(pblcKeyTbl); i++ {
					fmt.Println("       ", devIDCredentialTbl[i].credentialIndex, "      |    ", devIDCredentialTbl[i].pubkeyIndex, "   | ", devIDCredentialTbl[i].enable, " | ", devIDCredentialTbl[i].credential, "\n")
				}

			case 4:

				var devIDCredentialchain []DevIDCredentialChainStruct
				var crindx int
				crindx = -1
				fmt.Println("Enter the credential index:\n")
				fmt.Scanln(&crindx)
				if (0 <= crindx) && (crindx < len(devIDCredentialTbl)) {

					devIDCredentialchain = nil
					devIDCredentialchain = EnumerationOfDevIDCredentialChain(crindx)
					fmt.Println("******************************************************************Enumeration Chain Credentials************************************************************************************************************************")
					if len(devIDCredentialchain) == 0 {
						fmt.Println(" Chain cert not found!! ", "\n")
					} else {
						fmt.Println("ChainIndex | Chain Credential")
						for i := 0; i < len(devIDCredentialchain); i++ {
							fmt.Println("  ", devIDCredentialchain[i].credentialChainIndex, "    | ", devIDCredentialchain[i].credentialChainCredential, "\n")
						}
					}

				} else {
					fmt.Println("Please enter the correct DevID credential index!")
				}

			case 5:

				var currentEncoding, dataOctets string
				var dataLength int
				currentEncoding = "ECDSADIGESTINFO_OPAQUE"
				fmt.Println("Enter the data to be signed:\n")
				fmt.Scanln(&dataOctets)
				dataLength = len(dataOctets)
				var flg bool
				var crPubindx int
				crPubindx = -1
				fmt.Println("Enter the public key index:\n")
				fmt.Scanln(&crPubindx)
				if (0 <= crPubindx) && (crPubindx < len(pblcKeyTbl)) {
					flg, signR, signS = Signing(crPubindx, currentEncoding, dataLength, dataOctets)
					fmt.Println("******************************************************************Signing****************************************************************************************************************************************\n")
					fmt.Println("Status:", flg, "Signature: ", signR, signS, "\n")
				} else {
					fmt.Println("Please enter the correct public key index!")

				}

			case 6:
				fmt.Println("******************************************************************DevIDCredential Enable*************************************************************************************************************************")
				var flgEnable bool
				var crindx1 int
				crindx1 = -1
				fmt.Println("Enter the credential index:\n")
				fmt.Scanln(&crindx1)
				if (0 <= crindx1) && (crindx1 < len(devIDCredentialTbl)) {

					flgEnable = DevIDCredentialEnable(crindx1)
					if flgEnable == true {
						fmt.Println("DevID credential index ", crindx1, "is enabled!!", "\n")
					} else {
						fmt.Println("DevID credential index ", crindx1, "can not be enabled!!", "\n")
					}
				} else {
					fmt.Println("Please enter the correct DevID credential index!")
				}

			case 7:

				fmt.Println("******************************************************************DevIDCredential Disable************************************************************************************************************************")
				var flgDisable bool
				var crindx2 int
				crindx2 = -1
				fmt.Println("Enter the credential index:\n")
				fmt.Scanln(&crindx2)
				if (0 <= crindx2) && (crindx2 < len(devIDCredentialTbl)) {
					flgDisable = DevIDCredentialDisable(crindx2)
					if flgDisable == true {
						fmt.Println("DevID credential index ", crindx2, "is disabled!!", "\n")
					} else {
						fmt.Println("DevID credential index ", crindx2, "can not be disabled!!", "\n")
					}
				} else {
					fmt.Println("Please enter the correct DevID credential index!")
				}

			case 8:
				fmt.Println("******************************************************************DevID Key Ennable******************************************************************************************************************************")
				var flgKeyEnable bool
				var keyindx1 int
				keyindx1 = -1
				fmt.Println("Enter the public key index:\n")
				fmt.Scanln(&keyindx1)
				if (0 <= keyindx1) && (keyindx1 < len(pblcKeyTbl)) {
					flgKeyEnable = DevIDKeyEnable(keyindx1)
					if flgKeyEnable == true {
						fmt.Println("Public key index ", keyindx1, "is enabled!!", "\n")
					} else {
						fmt.Println("Public key index ", keyindx1, "can not be enabled!!", "\n")
					}
				} else {
					fmt.Println("Please enter the correct public key index!")

				}

			case 9:
				fmt.Println("******************************************************************DevID Key Disable******************************************************************************************************************************")
				var flgKeyDisable bool
				var keyindx2 int
				fmt.Println("Enter the public key index:\n")
				fmt.Scanln(&keyindx2)
				if (0 <= keyindx2) && (keyindx2 < len(pblcKeyTbl)) {
					flgKeyDisable = DevIDKeyDisable(keyindx2)
					if flgKeyDisable == true {
						fmt.Println("Public key index ", keyindx2, "is disabled!!", "\n")
					} else {
						fmt.Println("Public key index ", keyindx2, "can not be disabled!!", "\n")
					}
				} else {
					fmt.Println("Please enter the correct public key index!")

				}

			case 10:
				break
			default:

				fmt.Println("Select from the operation listed below (1-10)!!!")
			}

			///////////////////////////////////////////////////////////////////////////////////////////////////////////

		}

	}
	
}
