#!/bin/bash

openssl req -x509 -sha256 -nodes -days 356 -newkey rsa:2048 -keyout client.key -out client.crt