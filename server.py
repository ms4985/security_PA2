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
import time

#globals
SIZE = 10000
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
tls_server = wrap_socket(server, ssl_version=PROTOCOL_TLSv1, 
							server_side=True, certfile='server.crt', 
							keyfile = 'server.key', ca_certs='client.crt', 
							cert_reqs=CERT_REQUIRED)

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
			out = handle_get(data)

			#if file cannot be opened, send error
			if 'ERROR' in out:
				sock.send(out)

			#else send the file and hash
			else:
				sock.send(out[0])
				time.sleep(1)
				sock.send(out[1])

		#remove the	client socket from connections and close it	
		if cmd[0] == 'stop':
			connections.remove(sock)
			sock.close()
	except:
		#no data received by client so move on
		pass

#receive the file and hash from the client and write it to a file
def handle_put(data, sock):
	data = data.split()
	fname = data[1]
	File = sock.recv(SIZE)
	with open( fname, 'wb') as f:
		f.write(File)
	Hash = sock.recv(SIZE)
	with open(fname + '.sha256', 'wb') as f:
		f.write(Hash)

#try to open the file and hash and return error string upon failure
def handle_get(data):
	data = data.split()
	fname = data[1]
	try:
		with open(fname, 'rb') as f:
			File = f.read()
	except:
		string = 'ERROR: ' + fname + ' cannot be retrieved'
		return string
	try:
		with open(fname + '.sha256', 'rb') as f:
			Hash = f.read()
	except:
		return 'ERROR: Hash file cannot be retrieved'
	return File, Hash
	

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

