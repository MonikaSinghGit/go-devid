   # edit directory here, or override
   #export cadir=${rt}/ca
   #mkdir $cadir
   sq=45
   export rt=root
   mkdir $rt
   
   export cadir=${cadir-$rt/ca}
   echo $cadir 
   mkdir $cadir
   export rootca=${cadir}/root
   export cfgdir=${cfgdir-$cadir}
   #echo $cfgdir
   export intdir=${cadir}/intermediate
   export int1ardir=${cadir}/inter_1ar
   export format=pem
   export default_crl_days=65

   mkdir -p $cadir/certs
   mkdir -p $rootca
   (cd $rootca
   mkdir -p certs crl csr newcerts private
   chmod 700 private
   touch index.txt index.txt.attr
   if [ ! -f serial ]; then echo 00 >serial; fi
   )

   sn=8

   # edit these to suit
   countryName="/C=US"
   stateOrProvinceName="/ST=MI"
   localityName="/L=Oak Park"
   organizationName="/O=HTT Consulting"
   #organizationalUnitName="/OU="
   organizationalUnitName=
   commonName="/CN=Root CA"
   DN=$countryName$stateOrProvinceName$localityName
   DN=$DN$organizationName$organizationalUnitName$commonName

   echo $DN
   export subjectAltName=email:postmaster@htt-consult.com

   export default_crl_days=2048
   
   ##########################################rootcert###################################################
   
   
   
    export pass=pass:hello
	export passin=pass:hello

	# Create passworded keypair file

	if [ ! -f $rootca/private/ca.key.$format ]; then
		echo GENERATING KEY
		openssl genpkey -pass $pass -aes256 -algorithm ec\
				-pkeyopt ec_paramgen_curve:prime256v1\
				-outform $format -pkeyopt ec_param_enc:named_curve\
				-out $rootca/private/ca.key.$format
		chmod 400 $rootca/private/ca.key.$format
		openssl pkey -passin $passin -inform $format -in $rootca/private/ca.key.$format\
				-text -noout
	fi

	# Create Self-signed Root Certificate file
	# 7300 days = 20 years; Intermediate CA is 10 years.

	echo GENERATING and SIGNING REQ
	openssl req -config $cfgdir/openssl-root.cnf -passin $passin \
		 -set_serial 0x$(openssl rand -hex $sn)\
		 -keyform $format -outform $format\
		 -key $rootca/private/ca.key.$format -subj "$DN"\
		 -new -x509 -days 7300 -sha256 -extensions v3_ca\
		 -out $cadir/certs/ca.cert.$format

	#

	openssl x509 -inform $format -in $cadir/certs/ca.cert.$format\
		 -text -noout
	openssl x509 -purpose -inform $format\
		 -in $cadir/certs/ca.cert.$format -inform $format
   
   
   
   
   #############################Intermediate pki###########################
   
   # export intdir=${intdir-$cadir/intermediate}
   # mkdir -p $intdir

   # (
   # cd $intdir
   # mkdir -p certs crl csr newcerts private
   # chmod 700 private
   # touch index.txt index.txt.attr
   # if [ ! -f serial ]; then echo 00 >serial; fi
   # )

   # sn=8 # hex 8 is minimum, 19 is maximum
   # echo 1000 > $intdir/crlnumber

   # # cd $dir
   # export crlDP=
   # # For CRL support use uncomment these:
   # crl=intermediate.crl.pem
   # crlurl=www.htt-consult.com/pki/$crl
   # export crlDP="URI:http://$crlurl"
   # export default_crl_days=30
   # export ocspIAI=
   # # For OCSP support use uncomment these:
   # #ocspurl=ocsp.htt-consult.com
   # #export ocspIAI="OCSP;URI:http://$ocspurl"

   # commonName="/CN=Signing CA"
   # DN=$countryName$stateOrProvinceName$localityName$organizationName
   # DN=$DN$organizationalUnitName$commonName
   # echo $DN
   
   
   # #####################################Intermediate Certificate##########################################
   
   # # Create passworded keypair file

	# if [ ! -f $intdir/private/intermediate.key.$format ]; then
		# echo GENERATING intermediate KEY
		# openssl genpkey -pass $pass -aes256 -algorithm ec \
		            # -pkeyopt ec_paramgen_curve:prime256v1 \
					# -outform $format -pkeyopt ec_param_enc:named_curve\
					# -out $intdir/private/intermediate.key.$format
		# chmod 400 $intdir/private/intermediate.key.$format
		# openssl pkey -passin $passin -inform $format\
				# -in $intdir/private/intermediate.key.$format -text -noout
	# fi

	# # Create the CSR

	# echo GENERATING and SIGNING REQ intermediate
	# openssl req -config $cfgdir/openssl-root.cnf -passin $passin \
		# -key $intdir/private/intermediate.key.$format -batch \
		# -keyform $format -outform $format -subj "$DN" -new -sha256\
		# -out $intdir/csr/intermediate.csr.$format
	# openssl req -text -noout -verify -inform $format\
		# -in $intdir/csr/intermediate.csr.$format


	# # Create Intermediate Certificate file

	# openssl rand -hex $sn > $intdir/serial # hex 8 is minimum, 19 is maximum

	# if [ ! -f $cadir/certs/intermediate.cert.pem ]; then
		# # Note 'openssl ca' does not support DER format
		# openssl ca -config $cfgdir/openssl-root.cnf -days 3650 -passin $passin \
				# -extensions v3_intermediate_ca -notext -md sha256 -batch \
				# -in $intdir/csr/intermediate.csr.$format\
				# -out $cadir/certs/intermediate.cert.pem
		# chmod 444 $cadir/certs/intermediate.cert.$format
		# rm -f $cadir/certs/ca-chain.cert.$format
	# fi

	# openssl verify -CAfile $cadir/certs/ca.cert.$format\
		 # $cadir/certs/intermediate.cert.$format

	# openssl x509 -noout -text -in $cadir/certs/intermediate.cert.$format

	# # Create the certificate chain file

	# if [ ! -f $cadir/certs/ca-chain.cert.$format ]; then
		# cat $cadir/certs/intermediate.cert.$format\
			# $cadir/certs/ca.cert.$format > $cadir/certs/ca-chain.cert.$format
		# chmod 444 $cadir/certs/ca-chain.cert.$format
	# fi
   
   
   
   ###################################### EE pki #################################################################
   
   # export dir=$cadir
   
   # (cd $dir
   # mkdir -p crl csr newcerts private
   # chmod 700 private
   # touch index.txt index.txt.attr
   # if [ ! -f serial ]; then echo 00 >serial; fi
   # )
   
   
   # commonName="/CN=EndEntity"
   # DN=$countryName$stateOrProvinceName$localityName
   # DN=$DN$organizationName$organizationalUnitName$commonName
   # echo $DN
   # serverfqdn=www.example.com
   # emailaddr=postmaster@htt-consult.com
   # export subjectAltName="DNS:$serverfqdn, email:$emailaddr"
   # echo $subjectAltName
   # openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1\
       # -pkeyopt ec_param_enc:named_curve\
       # -out $dir/private/$serverfqdn.key.$format
   # chmod 400 $dir/private/$serverfqdn.key.$format
   # openssl pkey -in $dir/private/$serverfqdn.key.$format -text -noout
   # openssl req -config $dir/openssl-intermediate.cnf\
       # -key $dir/private/$serverfqdn.key.$format \
       # -subj "$DN" -new -sha256 -out $dir/csr/$serverfqdn.csr.$format

   # openssl req -text -noout -verify -in $dir/csr/$serverfqdn.csr.$format

   # openssl rand -hex $sn > $dir/serial # hex 8 is minimum, 19 is maximum
   # # Note 'openssl ca' does not support DER format
   # openssl ca -config $dir/openssl-intermediate.cnf -days 375\
       # -extensions server_cert -notext -md sha256 \
       # -in $dir/csr/$serverfqdn.csr.$format\
       # -out $dir/certs/$serverfqdn.cert.$format
   # chmod 444 $dir/certs/$serverfqdn.cert.$format

   # openssl verify -CAfile $dir/certs/ca-chain.cert.$format\
        # $dir/certs/$serverfqdn.cert.$format
   # openssl x509 -noout -text -in $dir/certs/$serverfqdn.cert.$format
   
   
   
   # ################# EE certificate##############################################
   
    # commonName="/CN=EE EndEntity"
    # UserID="/UID=rgm"
    # DN=$countryName$stateOrProvinceName$localityName
    # DN=$DN$organizationName$organizationalUnitName$commonName$UserID
    # echo $DN
    # clientemail=rgm@example.com

	# export subjectAltName="email:$clientemail"
	# echo $subjectAltName

	# if [ ! -f $intdir/private/$clientemail.key.$format ]; then
		# openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1\
				# -pkeyopt ec_param_enc:named_curve\
				# -out $intdir/private/$clientemail.key.$format
		# chmod 400 $intdir/private/$clientemail.key.$format
		# openssl pkey -passin $passin -in $intdir/private/$clientemail.key.$format -text -noout
	# fi

	# openssl req -config $cfgdir/openssl-intermediate.cnf -passin $passin \
		# -key $intdir/private/$clientemail.key.$format \
		# -subj "$DN" -new -sha256 -out $intdir/csr/$clientemail.csr.$format

	# openssl req -text -noout -verify\
		# -in $intdir/csr/$clientemail.csr.$format

	# openssl rand -hex $sn > $intdir/serial # hex 8 is minimum, 19 is maximum
	# # Note 'openssl ca' does not support DER format
	# openssl ca -config $cfgdir/openssl-intermediate.cnf -days 375\
		# -extensions usr_cert -notext -md sha256 -passin $passin \
		# -in   $intdir/csr/$clientemail.csr.$format -batch\
		# -out  $cadir/certs/$clientemail.cert.$format
	# chmod 444 $cadir/certs/$clientemail.cert.$format

	# openssl verify -CAfile $cadir/certs/ca-chain.cert.$format\
		 # $cadir/certs/$clientemail.cert.$format
	# openssl x509 -noout -text -in $cadir/certs/$clientemail.cert.$format
   
   
   
   ####################################### 802.1AR Intermediate pki########################################
   export dir=$cadir/8021ARintermediate
   mkdir $dir
   cd $dir
   mkdir certs crl csr newcerts private
   chmod 700 private
   touch index.txt
   sn=8 # hex 8 is minimum, 19 is maximum
   echo 1000 > crlnumber

   # cd $dir
   #export crlDP=
   # For CRL support use uncomment these:
   crl=8021ARintermediate.crl.pem
   crlurl=www.htt-consult.com/pki/$crl
   export crlDP="URI:http://$crlurl"
   export default_crl_days=30
   export ocspIAI=
   # For OCSP support use uncomment these:
   #ocspurl=ocsp.htt-consult.com
   #export ocspIAI="OCSP;URI:http://$ocspurl"

   countryName="/C=US"
   stateOrProvinceName="/ST=MI"
   localityName="/L=Oak"
   organizationName="/O=HTT2"
   organizationalUnitName="/OU=Devices"
   #organizationalUnitName=
   commonName="/CN=802.1AR CA"$sq
   DN=$countryName$stateOrProvinceName$localityName$organizationName
   DN=$DN$organizationalUnitName$commonName
   echo $DN
   export subjectAltName=email:postmaster@htt-consult.com
   echo $subjectAltName
   
   
   
   ##changes
   cd ..
   cd ..
   cd ..
   
   ######################################## 802.1AR Intermediate Certificate#########################################################
   
  
   
      # Create passworded keypair file

   echo genpkey -aes256 -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1 -outform $format -pkeyopt ec_param_enc:named_curve -out $dir/private/8021ARintermediate.key.$format
   openssl genpkey -aes256 -algorithm ec\
       -pkeyopt ec_paramgen_curve:prime256v1 \
       -outform $format -pkeyopt ec_param_enc:named_curve\
       -out $dir/private/8021ARintermediate.key.$format
	 #changes below  
   chmod 400 $dir/private/8021ARintermediate.key.$format
   openssl pkey -inform $format\
       -in $dir/private/8021ARintermediate.key.$format -text -noout

   # Create the CSR

   openssl req -config $cadir/openssl-root.cnf\
       -key $dir/private/8021ARintermediate.key.$format \
       -keyform $format -outform $format -subj "$DN" -new -sha256\
       -out $dir/csr/8021ARintermediate.csr.$format
   openssl req -text -noout -verify -inform $format\
       -in $dir/csr/8021ARintermediate.csr.$format


   # Create 802.1AR Intermediate Certificate file
   # The following does NOT work for DER

   openssl rand -hex $sn > $dir/serial # hex 8 is minimum, 19 is maximum
   # Note 'openssl ca' does not support DER format
   openssl ca -config $cadir/openssl-root.cnf -days 3650\
       -extensions v3_intermediate_ca -notext -md sha256\
       -in $dir/csr/8021ARintermediate.csr.$format\
       -out $dir/certs/8021ARintermediate.cert.pem

   chmod 444 $dir/certs/8021ARintermediate.cert.$format

   openssl verify -CAfile $cadir/certs/ca.cert.$format\
        $dir/certs/8021ARintermediate.cert.$format

   openssl x509 -noout -text\
        -in $dir/certs/8021ARintermediate.cert.$format

   # Create the certificate chain file

   cat $dir/certs/8021ARintermediate.cert.$format\
      $cadir/certs/ca.cert.$format > $dir/certs/ca-chain.cert.$format
   chmod 444 $dir/certs/ca-chain.cert.$format

   
   ############################iDevID certofocate#############
      
	DevID=DI$sq
	countryName=
	stateOrProvinceName=
	localityName=
	organizationName="/O=HTT"
	organizationalUnitName="/OU=Devices"
	commonName=
	serialNumber="/serialNumber=$DevID"
	DN=$countryName$stateOrProvinceName$localityName
	DN=$DN$organizationName$organizationalUnitName$commonName
	DN=$DN$serialNumber
	echo $DN

	# hwType is OID for HTT Consulting, devices, sensor widgets
	export hwType=1.3.6.1.4.1.6715.10.1
	export hwSerialNum=01020304 # Some hex
	export subjectAltName="otherName:1.3.6.1.5.5.7.8.4;SEQ:hmodname, URI:https://mud.com"
	echo  $hwType - $hwSerialNum

	if [ ! -f $dir/private/$DevID.key.$format ]; then
		openssl genpkey -pass $pass -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1\
				-pkeyopt ec_param_enc:named_curve\
				-out $dir/private/$DevID.key.$format
		chmod 400 $dir/private/$DevID.key.$format
	fi

	openssl pkey -in $dir/private/$DevID.key.$format -text -noout
	openssl req -config $cfgdir/openssl-8021ARintermediate.cnf\
		-key $dir/private/$DevID.key.$format \
		-subj "$DN" -new -sha256 -out $dir/csr/$DevID.csr.$format

	openssl req -text -noout -verify\
		-in $dir/csr/$DevID.csr.$format
	#openssl asn1parse -i -in $dir/csr/$DevID.csr.pem
	# offset of start of hardwareModuleName and use that in place of 189
	#openssl asn1parse -i -strparse 10 -in $dir/csr/$DevID.csr.pem

	openssl rand -hex $sn > $dir/serial # hex 8 is minimum, 19 is maximum
	# Note 'openssl ca' does not support DER format
	echo ca -config $cfgdir/openssl-8021ARintermediate.cnf -days 375 -extensions 8021ar_idevid -notext -md sha256 -in $dir/csr/$DevID.csr.$format -out $dir/certs/$DevID.cert.$format
	openssl ca -config $cfgdir/openssl-8021ARintermediate.cnf -days 375\
		-extensions 8021ar_idevid -notext -md sha256 \
		-in $dir/csr/$DevID.csr.$format\
		-out $dir/certs/$DevID.cert.$format
	chmod 444 $dir/certs/$DevID.cert.$format

	openssl verify -CAfile $dir/certs/ca-chain.cert.$format\
		 $dir/certs/$DevID.cert.$format
	openssl x509 -noout -text -in $dir/certs/$DevID.cert.$format
	#openssl asn1parse -i -in $dir/certs/$DevID.cert.pem

	# offset of start of hardwareModuleName and use that in place of 493
	#openssl asn1parse -i -strparse 135 -in $dir/certs/$DevID.cert.pem

   
   
   
   
 
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   
   