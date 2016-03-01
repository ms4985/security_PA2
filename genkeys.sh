#!/bin/bash

#Megan Skrypek
#ms4985

openssl rsa -in server.key -pubout > s_pubkey.pem
openssl rsa -in server.key > s_privkey.pem

openssl rsa -in client.key -pubout > c_pubkey.pem
openssl rsa -in client.key > c_privkey.pem
