#!/bin/bash

rm -f test_*
rm -f allowed_signers



echo
echo "(1) Generate DSA key pair"
echo "========================="
ssh-keygen -t dsa -f test_dsa -N '' -C test@sshsig.profhenry.de

echo
echo "(1a) Convert DSA private key to PKCS#8"
echo "======================================"
echo "Writing as PEM"
cp test_dsa test_dsa_pkcs8
ssh-keygen -p -f test_dsa_pkcs8 -N '' -m pkcs8
echo "Writing as DER"
cat test_dsa_pkcs8 | head -n -1 | tail -n +2 | tr -d '\n' | base64 -d > test_dsa_pkcs8.der

echo
echo "(1b) Convert DSA public key to X.509"
echo "===================================="
echo "Writing as PEM"
ssh-keygen -e -f test_dsa -m pkcs8 > test_dsa.pub_x509
echo "Writing as DER"
cat test_dsa.pub_x509 | head -n -1 | tail -n +2 | tr -d '\n' | base64 -d > test_dsa.pub_x509.der



echo
echo "(2) Generate RSA key pair"
echo "========================="
ssh-keygen -t rsa -f test_rsa -N '' -C test@sshsig.profhenry.de

echo
echo "(2a) Convert RSA private key to PKCS#8"
echo "======================================"
echo "Writing as PEM"
cp test_rsa test_rsa_pkcs8
ssh-keygen -p -f test_rsa_pkcs8 -N '' -m pkcs8
echo "Writing as DER"
cat test_rsa_pkcs8 | head -n -1 | tail -n +2 | tr -d '\n' | base64 -d > test_rsa_pkcs8.der

echo
echo "(2b) Convert RSA public key to X.509"
echo "===================================="
echo "Writing as PEM"
ssh-keygen -e -f test_rsa -m pkcs8 > test_rsa.pub_x509
echo "Writing as DER"
cat test_rsa.pub_x509 | head -n -1 | tail -n +2 | tr -d '\n' | base64 -d > test_rsa.pub_x509.der



echo
echo "(3) Generate ED25519 key pair"
echo "============================="
ssh-keygen -t ed25519 -f test_ed25519 -N '' -C test@sshsig.profhenry.de

echo
echo "(3a) Convert ED25519 private key to PKCS#8"
echo "=========================================="
echo "Writing as DER"
cat test_ed25519 | (
  printf \\x30\\x2e\\x02\\x01\\x00\\x30\\x05\\x06\\x03\\x2b\\x65\\x70\\x04\\x22\\x04\\x20
  grep -Ev "^-" | tr -d '\n' | base64 -d | dd bs=161 skip=1 2>/dev/null | dd bs=32 count=1 2>/dev/null
) > test_ed25519_pkcs8.der
echo "Writing as PEM"
openssl pkey -in test_ed25519_pkcs8.der -inform der -outform pem > test_ed25519_pkcs8 

echo
echo "(3b) Convert ED25519 public key to X.509"
echo "========================================"
echo "Writing as DER"
openssl pkey -in test_ed25519_pkcs8.der -inform der -pubout -outform der > test_ed25519.pub_x509.der
echo "Writing as PEM"
openssl pkey -in test_ed25519_pkcs8.der -inform der -pubout -outform pem > test_ed25519.pub_x509



echo
echo "(4) Register all public keys as allowed signer"
echo "=============================================="
awk '{ print $3" "$1" "$2 }' test_dsa.pub >> allowed_signers
awk '{ print $3" "$1" "$2 }' test_rsa.pub >> allowed_signers
awk '{ print $3" "$1" "$2 }' test_ed25519.pub >> allowed_signers
