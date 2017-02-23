#!/bin/bash 

CiphersuitesRsa=(
  TLS-RSA-WITH-AES-128-CBC-SHA256
  TLS-RSA-WITH-AES-256-CBC-SHA256
  TLS-RSA-WITH-AES-128-GCM-SHA256
  TLS-RSA-WITH-AES-256-GCM-SHA384
  TLS-RSA-WITH-AES-128-CCM
  TLS-RSA-WITH-AES-256-CCM
  TLS-RSA-WITH-AES-128-CCM-8
  TLS-RSA-WITH-AES-256-CCM-8
  TLS-RSA-WITH-NULL-SHA256
)

CiphersuitesDh=(
  TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
  TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
  TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
  TLS-DHE-RSA-WITH-AES-256-GCM-SHA384
)

CiphersuitesEc=(
  TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256
  TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384
  TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256
  TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
)

CiphersuitesEcc=(
  TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256
  TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384
  TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
  TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384
)
#echo ${Ciphersuites[@]}

test_ciphersuite ()
{
    for i in {0..100}
    do
#	echo $i
	/home/mkoi/mbedtls/programs/ssl/ssl_client2 force_version=tls1_2 auth_mode=required ca_file=$3 crt_file=$4 key_file=$5 force_ciphersuite=$1 server_port=$2 > /dev/null
	i=$[i+1]
    done
}
 
j=0

#for cipher in "${CiphersuitesEcc[@]}";
#do
#    for one_test_case in {0..100}
#    do
#	start=`date +%s.%N`
#	test_ciphersuite "$cipher" "443" "/home/mkoi/cecerts/localh.crt" "/home/mkoi/cecerts/localh_c.crt" "/home/mkoi/cecerts/localh_c.pem"
#	end=`date +%s.%N`
#	runtime=$(python -c "print(${end} - ${start})")
#	echo "$one_test_case, $runtime" >> $cipher
#    done
#done

for cipher in "${CiphersuitesEc[@]}";
do
    for one_test_case in {0..100}
    do
	start=`date +%s.%N`
	test_ciphersuite "$cipher" "4443" "/home/mkoi/certs/localhost.crt" "/home/mkoi/certs/localhost_c.crt" "/home/mkoi/certs/localhost_c.pem"
	end=`date +%s.%N`
	runtime=$(python -c "print(${end} - ${start})")
	echo "$one_test_case, $runtime" >> $cipher
    done
done

for cipher in "${CiphersuitesDh[@]}";
do
    for one_test_case in {0..100}
    do
	start=`date +%s.%N`
	test_ciphersuite "$cipher" "4443" "/home/mkoi/certs/localhost.crt" "/home/mkoi/certs/localhost_c.crt" "/home/mkoi/certs/localhost_c.pem"
	end=`date +%s.%N`
	runtime=$(python -c "print(${end} - ${start})")
	echo "$one_test_case, $runtime" >> $cipher
    done
done


