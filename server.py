# Megan Skrypek
# ms4985

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from socket import *
import sys
import select
from ssl import *
import pickle

#globals
SIZE = 4096
BLOCK_SIZE = 16
connections = []
aes_mode = AES.MODE_CBC

#handle user input
if len(sys.argv) != 2:
	print 'ERROR: not enough arguments'
	sys.exit()

host, port = '', int(sys.argv[1])
if ((port < 1024) or (port > 49151)):
	print 'ERROR: invalid port'
	sys.exit()

#set up server socket
server = socket(AF_INET, SOCK_STREAM)
server.bind((host,port))
print "server is running on: ", gethostbyname(gethostname())
server.listen(5)
print "server listening for clients..."
connections.append(server)

#wrap in tls
tls_server = wrap_socket(server, ssl_version=PROTOCOL_TLSv1, server_side=True, certfile='server.crt', keyfile = 'server.key', ca_certs='client.crt', cert_reqs=CERT_REQUIRED)

#handles receiving data from the client
#client sends a keyword first to the server
#then the server responds accordingly with the correct helper fn
def handle_client(sock, address):
	try:
		data = sock.recv(SIZE)
		cmd = data.split()
		if cmd[0] == 'put':
			handle_put(data, sock)
		if cmd[0] == 'get':
			print data
		if cmd[0] == 'stop\n':
			print data
		else:
			sock.send("invalid command")	

	except:
		#no data received by client so move on
		pass

#receive file from client
#parse original size of plaintext
#parse iv and use for decryptor
#if untrusted mode, read from fakefile and use as plaintext
#	if fakefile is not padded, verfication failed
#if trusted mode, decrypt plaintext and save to file
def handle_file(sock):
	ctxt = sock.recv(SIZE)
	size = ctxt[:BLOCK_SIZE]
	iv = ctxt[BLOCK_SIZE:BLOCK_SIZE*2]
	ctxt = ctxt[BLOCK_SIZE*2:]
	decryptor = AES.new(KEY, aes_mode, iv)
	global plain
	if (len(ctxt) % BLOCK_SIZE) != 0:
		plain = 'ERROR'
		return
	plain = decryptor.decrypt(ctxt)
	plain = plain[:int(size)]
	with open('decryptedfile', 'wb') as f:
		f.write(plain)

def handle_put(data, sock):
	print 'in handleput'
	data = data.split()
	fname = data[1]
	flag = data[2]
	if flag == 'E':
		passwd = data[3]
	print 'after data handle'
	File = sock.recv(SIZE)
	with open(fname, 'w') as f:
		f.write(File)
	Hash = sock.recv(SIZE)
	with open(fname + '.sha256', 'w') as f:
		f.write(Hash)
	print 'after opens'

#handle data send from client connections		
try:
	while 1:
		read, write, error = select.select(connections, [], [])
		for sock in read:
			if sock == server:
				#accept incoming connections
				socket, address = tls_server.accept()
				socket.send("connected!")
				connections.append(socket)
				print 'client connected'
			else:
				try:
					#client helper function
					handle_client(socket, address)
				except:
					#client has disconnected
					sock.close()
#catch ctrl-c interrupts to exit
except (KeyboardInterrupt, SystemExit):
	print "\nserver shutting down..."
	server.close()
	sys.exit()

