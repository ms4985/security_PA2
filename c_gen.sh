#!/bin/bash

openssl genrsa -des3 -out client.orig.key 2048
openssl rsa -in client.orig.key -out client.key
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 1 -in client.csr -signkey client.key -out client.crt
