#!/bin/bash

# Script generates test CRL revocation and generates CRL list for each self-signed cert

check_result(){
    if [ $1 -ne 0 ]; then
        echo "Step failed, Abort"
        exit 1
    else
        echo "Step Succeeded!"
    fi
}

setup_files() {
    #set up the file system for updating the crls
    echo "setting up the file system for generating the crls..."
    echo ""
    mkdir demoCA || exit 1
    touch ./demoCA/index.txt || exit 1
    touch ./index.txt || exit 1
    touch ../crl/index.txt || exit 1
    touch ./crlnumber || exit 1
    touch ../crl/crlnumber || exit 1
    echo "01" >> crlnumber || exit 1
    echo "01" >> ../crl/crlnumber || exit 1
    touch ./blank.index.txt || exit 1
    touch ./demoCA/index.txt.attr || exit 1
    touch ../crl/index.txt.attr || exit 1
}

cleanup_files() {
    rm blank.index.txt || exit 1
    rm index.* || exit 1
    rm crlnumber* || exit 1
    rm -rf demoCA || exit 1
    echo "Removed ../wolfssl.cnf, blank.index.txt, index.*, crlnumber*, demoCA/"
    echo "        ../crl/index.txt"
    echo ""
    exit 0
}

# Args: 1=out, 2=cakey, 3=cacert, 4=days
gen_crl() {
    echo "openssl ca -config ../renewcerts/wolfssl.cnf -gencrl -crldays $4 -out $1 -keyfile $2 -cert $3"
    openssl ca -config ../renewcerts/wolfssl.cnf -gencrl -crldays $4 -out $1 -keyfile $2 -cert $3
    check_result $?

    # Add formatted info to pem
    echo "openssl crl -in $1 -text > tmp.pem"
    openssl crl -in $1 -text > tmp.pem
    check_result $?
    echo "mv tmp.pem $1"
    mv tmp.pem $1
    check_result $?
}

# Args: 1=in, 2=cakey, 3=cacert
crl_revoke() {
    echo "openssl ca -config ../renewcerts/wolfssl.cnf -revoke $1 -keyfile $2 -cert $3"
    openssl ca -config ../renewcerts/wolfssl.cnf -revoke $1 -keyfile $2 -cert $3
    check_result $?
}

trap cleanup_files EXIT


# setup the files
setup_files

# Generate revoked examples
# client-cert.pem (self signed)
gen_crl crl2.pem ../client-key.pem ../client-cert.pem 1000

# ca-cert.pem
crl_revoke ../server-revoked-cert.pem ../ca-key.pem ../ca-cert.pem
gen_crl crl.pem ../ca-key.pem ../ca-cert.pem 1000

# append crl and crl2 as new crl2
cat crl.pem crl2.pem > tmp.pem
mv tmp.pem crl2.pem

# server-cert.pem
crl_revoke ../server-cert.pem ../ca-key.pem ../ca-cert.pem
gen_crl crl.revoked ../ca-key.pem ../ca-cert.pem 1000

# remove revoked so next time through the normal CA won't have server revoked
cp blank.index.txt demoCA/index.txt

# ca-ecc-cert.pem (root CA)
gen_crl caEccCrl.pem ../ca-ecc-key.pem ../ca-ecc-cert.pem 1000

# ca-ecc384-cert.pem (root CA)
gen_crl caEcc384Crl.pem ../ca-ecc384-key.pem ../ca-ecc384-cert.pem 1000

# client-cert.pem (self signed)
gen_crl cliCrl.pem ../client-key.pem ../client-cert.pem 1000

# client-ecc-cert.pem (self signed)
gen_crl eccCliCRL.pem ../ecc-client-key.pem ../client-ecc-cert.pem 1000

# ca-int-cert.pem (intermediate CA)
gen_crl ca-int.pem ../intermediate/ca-int-key.pem ../intermediate/ca-int-cert.pem 1000

# ca-int-ecc-cert.pem (intermediate CA)
gen_crl ca-int-ecc.pem ../intermediate/ca-int-ecc-key.pem ../intermediate/ca-int-ecc-cert.pem 1000


exit 0
