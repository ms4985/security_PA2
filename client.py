# Megan Skrypek
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

#deterministic random number generator that uses password as a seed
#produces a 16 integer key
def compute_key(seed):
	random.seed(seed)
	key = ''
	for i in range(0,16):
		key += str(random.randint(0,9))
	return key

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
def hash_file(fname):
	try:
		with open(fname, 'rb') as f:
			plaintext = f.read()
	except:
		return 'ERROR'
	h = SHA256.new(plaintext)
	return h

#parse original size of plaintext
#parse iv and use for decryptor
#if untrusted mode, read from fakefile and use as plaintext
#	if fakefile is not padded, verfication failed
#if trusted mode, decrypt plaintext and save to file
def decrypt_file(File, passwd):
	key = compute_key(passwd)
	size = File[:BLOCK_SIZE]
	i = File[BLOCK_SIZE:BLOCK_SIZE*2]
	File = File[BLOCK_SIZE*2:]
	try:
		decryptor = AES.new(key, mode, i)
	except:
		return 'ERROR'
	if (len(File) % BLOCK_SIZE) != 0:
		return 'ERROR'
	plain = decryptor.decrypt(File)
	plain = plain[:int(size)]
	return plain

def handle_put(fname, f, passwd):
	Hash = hash_file(fname)
	errstring =  'ERROR: ' + fname + ' cannot be transferred'
	if Hash == 'ERROR':
		return errstring
	if f == 'E':
		key = compute_key(passwd)
		Encfile = encrypt_file(key, fname)
		return Encfile, Hash
	else:
		try:
			with open(fname, 'rb') as f:
				plaintext = f.read()
			return plaintext, Hash
		except:
			return 'ERROR: ' + fname + ' was not transferred'

#parse command from client, return errors when necessary
def handle_msg(msg):
	passwd = ''
	m = msg.split()
	length = len(m)
	if length > 4:
		return 'ERROR: Too many parameters'
	elif length == 2:
		return 'ERROR: Missing parameters, minimum of a filename and \'N\' or \'E\' is requried'
	cmd = m[0]
	if cmd == 'stop':
		return cmd
	if ((cmd == 'put') and (length > 1)):
		fname = m[1]
		flag = m[2]
		if flag == 'E':
			if length != 4:
				return 'ERROR: Missing parameters, \"E\" requires a password'
			passwd = m[3]
		elif flag == 'N':
			pass
		else:
			return 'ERROR: Invalid parameter ' + '\'' + flag + '\''
		return handle_put(fname, flag, passwd)
	elif ((cmd == 'get') and (length > 1)):
		fname = m[1]
		flag = m[2]
		if flag == 'E':
			if length != 4:
				return 'ERROR: Missing parameters, \"E\" requires a password'
			passwd = m[3]
		elif flag == 'N':
			pass
		else:
			return 'ERROR: Invalid parameter ' + '\'' + flag + '\''
		return msg
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
					error = False
					#receive output of handle_msg helper fn
					out = handle_msg(msg)
					#if the output is not an error, send command to server for processing
					if out == 'stop':
						tls_client.send(msg)
					elif (('ERROR' not in out) and ('put' in msg)):
						tls_client.send(msg)
						#need to sleep in order to give server time to process
						time.sleep(1)
						tls_client.send(out[0])
						time.sleep(1)
						tls_client.send(out[1].hexdigest())
						msg = msg.split()
						print 'transfer of', msg[1], 'complete'
					elif (('ERROR' not in out) and ('get' in msg)):
						tls_client.send(msg)
						servFile = tls_client.recv(SIZE)
						if 'ERROR' in servFile:
							error = True
							print servFile
						msg = msg.split()
						if ((msg[2] == 'E') and (not error)):
							enc = decrypt_file(servFile, msg[3])
							if enc == 'ERROR':
								print 'ERROR: decryption of ' + msg[1] + ' failed, was file encrypted?'
								Hash = tls_client.recv(SIZE)
							else:
								h = SHA256.new(enc)
								Hash = tls_client.recv(SIZE)
								if h.hexdigest() == Hash:
									with open(msg[1], 'wb') as f:
										f.write(enc)
									print 'retrieval of', msg[1], 'complete'
								else:
									print 'ERROR: Computed hash of', msg[1], 'does not match retrieved hash'
						elif ((msg[2] == 'N') and (not error)):
							h = SHA256.new(servFile)
							Hash = tls_client.recv(SIZE)
							if h.hexdigest() == Hash:
								with open(msg[1], 'wb') as f:
									f.write(servFile)
								print 'retrieval of', msg[1], 'complete'
							else:
								print 'ERROR: Computed hash of', msg[1], 'does not match retrieved hash'
					else:
						print out

	#catch crtl-c interrupts
	except (KeyboardInterrupt, SystemExit):
		client.send('bye')
		client.close()
		sys.exit()
