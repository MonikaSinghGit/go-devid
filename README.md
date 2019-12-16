# SecureDeviceIdentityGoCode

1. DevID_pki.sh is the shell script to generate iDevId.\
    — Run the script and put passphrase: "hello".\
    — The iDevId, ca-chain and root certificate will be generated in the folder: root/ca/certs/

2. DevIDServices.go contains all necessary operations with idevID.\
    — Initialization\
    — Enumeration of the DevID public keys\
    — Enumeration of DevID credentials\
    — Enumeration of DevID credential chain\
    — Signing\
    — Enable/disable DevID credential\
    — Enable/disable of DevID key\
    Step 1. on running DevIDServices.go enter the DevID Modules available in the cert folder. ex. DevID45\
    Step 2. First, initialize the DevId.\
    Step 3. select the desired operation.
