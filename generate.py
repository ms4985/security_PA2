# Megan Skrypek
# ms4985

from Crypto.PublicKey import RSA

#SERVER:
#generate rsa key pairs and save to files
rsa_keys = RSA.generate(2048)
pubkey = rsa_keys.publickey().exportKey("PEM")
with open('s_pubkey.pem', 'w') as f:
	f.write(pubkey)
privkey = rsa_keys.exportKey("PEM")
with open('s_privkey.pem', 'w') as f:
	f.write(privkey)

#CLIENT:
#generate rsa key pair ans save to files
rsa_keys2 = RSA.generate(2048)
pubkey2 = rsa_keys2.publickey().exportKey("PEM")
with open('c_pubkey.pem', 'w') as f:
	f.write(pubkey2)
privkey2 = rsa_keys2.exportKey("PEM")
with open('c_privkey.pem', 'w') as f:
	f.write(privkey2)

