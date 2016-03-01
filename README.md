Megan Skrypek
ms4985
coms w4180
Programming Assignment 2

How to run the code:

	first generate the certificates using the shell scripts: s_gen.sh, c_gen.sh

		How to generate certificates:

			$ ./s_gen.sh
			You may be prompted for some information:
					enter any password 
					enter any country code
					enter any city
					enter any organization
					subject = server
					(left were left blank)

			$ ./c_gen.sh
			You may be prompted for some information:
					enter any password 
					enter any country code
					enter any city
					enter any organization
					subject = client
					(left were left blank)

	now, start the server and then the client

		$ python server.py <port>

		$ python client.py <ip address> <port>

	then, from the client side enter the commands: put, get, stop with the appropriate parameters

	Use stop to close the client down, and once client is closed use 'ctrl-c' to close the server

	NOTE: 'crtl-c' can be used to close the server at any time, however it does not go through evertime and I coudld not find the reason why