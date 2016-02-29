# Megan Skrypek
# ms4985
import time
#from Crypto.PublicKey import RSA
from OpenSSL import crypto, SSL


#SERVER:
#generate rsa key pairs and save to files
"""
rsa_keys = RSA.generate(2048)
pubkey = rsa_keys.publickey().exportKey("PEM")
with open('s_pubkey.pem', 'w') as f:
	f.write(pubkey)
privkey = rsa_keys.exportKey("PEM")
with open('s_privkey.pem', 'w') as f:
	f.write(privkey)
"""
#CLIENT:
#generate rsa key pair ans save to files
"""rsa_keys2 = RSA.generate(2048)
pubkey2 = rsa_keys2.publickey().exportKey("PEM")
with open('c_pubkey.pem', 'w') as f:
	f.write(pubkey2)
privkey2 = rsa_keys2.exportKey("PEM")
with open('c_privkey.pem', 'w') as f:
	f.write(privkey2)
"""

CERT_FILE = 'certfile.pem'
KEY_FILE = 'priv.pem'

skey = crypto.PKey()
skey.generate_key(crypto.TYPE_RSA, 2048)

ckey = crypto.PKey()
ckey.generate_key(crypto.TYPE_RSA, 2048)

cert = crypto.X509()
cert.get_subject().O = 'server'
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(3600) #certificate is good for one hour
cert.set_issuer(cert.get_subject())
cert.set_pubkey(skey)
cert.sign(skey, 'sha256')

with open(CERT_FILE, 'w') as f:
	f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
with open(KEY_FILE, 'w') as f:
	f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, skey))

