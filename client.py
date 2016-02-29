3# Megan Skrypek
# ms4985

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from socket import *
import sys
import select
from os import urandom
import random
import pickle
import time
from ssl import *

#globals
SIZE = 4096
BLOCK_SIZE = 16

#set up AES encryption
iv = urandom(BLOCK_SIZE)
mode = AES.MODE_CBC

#check number of arguments
if len(sys.argv) != 3:
	print 'ERROR: not enough arguments'
	sys.exit()

#handle user inputs
host = sys.argv[1]
"""
try:
	socket.inet_aton(host)
except:
	print 'ERROR: invalid ip address'
	sys.exit()
"""

port = int(sys.argv[2])
if ((port < 1024) or (port > 49151)):
	print 'ERROR: invalid port'
	sys.exit()

#encrypt the file using AES cipher in CBC mode
#read entire plaintext
#calculate original size and remainder when modding using block size
#pad the plaintext with null chars 
#prepend the ciphertext with original size and iv
#encrypt plaintext and append to ciiphertext
def encrypt_file(key, fname):
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
def hash_file(f):
	with open(f, 'rb') as f:
		plaintext = f.read()
	h = SHA256.new(plaintext)
	return h

def handle_put(fname, f):
	Hash = hash_file(fname)
	if f == 'E':
		random.seed(passwd)
		key = ''
		for i in range(0,16):
			key += str(random.randint(0,9))
		Encfile = encrypt_file(key, fname)
		print Hash.hexdigest()
		print Encfile
		return Encfile, Hash
	else:
		with open(fname, 'rb') as f:
			plaintext = f.read()
		return plaintext, Hash


def handle_get(fname, f):
	return 

#parse command from client, return errors when necessary
def handle_msg(msg):
	m = msg.split()
	if len(m) > 4:
		return 'ERROR: Too many parameters'
	elif len(m) == 2:
		return 'ERROR: Missing parameters, minimum of a filename and \'N\' or \'E\' is requried'
	cmd = m[0]
	if cmd == 'stop':
		return cmd
	fname = m[1]
	flag = m[2]
	if flag == 'E':
		passwd = m[3]
	elif flag == 'N':
		pass
	else:
		return 'ERROR: Invalid parameter ' + '\'' + flag + '\''
	if cmd == 'put':
		return handle_put(fname, f)
	elif cmd == 'get':
		return handle_get(fname, f)
	else:
		return 'ERROR: Invalid commands, options are \"get\" \"put\" \"stop\"'

#set up client socket
client = socket(AF_INET, SOCK_STREAM)
#wrap client in tls wrapper
tls_client = wrap_socket(client, certfile = 'client.crt', 
						keyfile = 'client.key', ca_certs='server.crt', 
						ssl_version=PROTOCOL_TLSv1, cert_reqs=CERT_REQUIRED)

#try to connect to server
try:
	print "connecting..."
	tls_client.connect((host, port))
except:
	print "no server on host/port"
	sys.exit()

#handle data sent from server
while 1:
	sockets = [sys.stdin, tls_client]
	read, write, error = select.select(sockets, [], [])
	try:
		for sock in read:
			if sock == tls_client:
				data = sock.recv(SIZE)
				#if there is data it should be the 'connected' respons
				#client prints message and begins transmitting to server
				#sends the encrypted key, encrypted file, and signature
				if data:
					print data
				#exit if server quit
				else:
					print "server disconnected"
					sys.exit()
			#send data to server
			else:
				#read in commands from client and only send to server if valid
				msg = sys.stdin.readline()
				if msg:
					#receive output of handle_msg helper fn
					out = handle_msg(msg)
					#if the output is not an error, send command to server for processing
					if out == 'stop':
						tls_client.send(msg)
					elif 'ERROR' not in out:
						tls_client.send(msg)
						#need to sleep in order to give server time to process
						time.sleep(1)
						tls_client.send(out[0])
						time.sleep(1)
						tls_client.send(out[1].hexdigest())
					else:
						print out

	#catch crtl-c interrupts
	except (KeyboardInterrupt, SystemExit):
		client.send('bye')
		client.close()
		sys.exit()
