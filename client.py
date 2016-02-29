# Megan Skrypek
# ms4985

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
import socket
import sys
import select
from os import urandom
import pickle
import time

#globals
SIZE = 4096
BLOCK_SIZE = 16

#set up AES encryption
iv = urandom(BLOCK_SIZE)
mode = AES.MODE_CBC

#check number of arguments
if len(sys.argv) != 5:
	print 'ERROR: not enough arguments'
	sys.exit()

#handle user inputs
host = sys.argv[1]
try:
	socket.inet_aton(host)
except:
	print 'ERROR: invalid ip address'
	sys.exit()

port = int(sys.argv[2])
if ((port < 1024) or (port > 49151)):
	print 'ERROR: invalid port'
	sys.exit()

key = sys.argv[3]
if len(key) != 16:
	print 'ERROR: password is not 16 characters long'
	sys.exit()

fname = sys.argv[4]

def encrypt_key():
	with open('s_pubkey.pem', 'r') as f:
		k = f.read()
		server_key = RSA.importKey(k)
	encrypted = server_key.encrypt(key, 16)
	return encrypted

#encrypt the file using AES cipher in CBC mode
#read entire plaintext
#calculate original size and remainder when modding using block size
#pad the plaintext with null chars 
#prepend the ciphertext with original size and iv
#encrypt plaintext and append to ciiphertext
def encrypt_file():
	encryptor = AES.new(key, mode, iv)
	with open(fname, 'rb') as f:
		plaintext = f.read()
	size = len(plaintext)
	rem = size % BLOCK_SIZE
	if rem < BLOCK_SIZE:
		plaintext+=' '*(BLOCK_SIZE-rem)
	length = str(size) + ' '*(BLOCK_SIZE-len(str(size)))
	ciphertext = length + iv
	ciphertext += encryptor.encrypt(plaintext)
	return ciphertext

#hash the file using SHA 256
#return the hash object
def hash_file():
	with open(fname, 'rb') as f:
		plaintext = f.read()
	h = SHA256.new(plaintext)
	return h

#sign the hash using RSA private key
#return the encrypted hash
def encrypt_hash(hash):
	with open('c_privkey.pem', 'r') as f:
		pk = RSA.importKey(f.read())
	signer = PKCS1_v1_5.new(pk)
	sig = signer.sign(hash)
	return sig	

#set up client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#try to connect to server
try:
	print "connecting..."
	client.connect((host, port))
except:
	print "no server on host/port"
	sys.exit()

#failsafe in case client doesnt disconnect
#prevents resending file, signature and key to server
sent = False

#handle data sent from server
while 1:
	sockets = [sys.stdin, client]
	read, write, error = select.select(sockets, [], [])
	try:
		for sock in read:
			if sock == client:
				data = sock.recv(SIZE)
				#if there is data it should be the 'connected' respons
				#client prints message and begins transmitting to server
				#sends the encrypted key, encrypted file, and signature
				if data:
					print data
					if sent == False:
						sock.send('key')
						ek = encrypt_key()
						ek = pickle.dumps(ek)
						sock.send(ek)
						ctxt = encrypt_file()
						time.sleep(1)
						sock.send('file')
						sock.send(ctxt)
						time.sleep(1)
						sock.send('signature')
						h = hash_file()
						signature = encrypt_hash(h)
						signature = pickle.dumps(signature)
						sock.send(signature)
						sent == True
						sys.exit()
				#exit if server quit
				else:
					print "server disconnected"
					sys.exit()
			#send data to server
			else:
				msg = sys.stdin.readline()
				if msg:
					client.send(msg)

	#catch crtl-c interrupts
	except (KeyboardInterrupt, SystemExit):
		client.send('bye')
		client.close()
		sys.exit()

