#
#	SCRAM Server
#	@author: Hayden McParlane
#	@creation-date: 4.9.2016

import sasl
from sasl import SecurityLayerFactory
import helper
import ssl
import socket

_ADDR = ("159.203.246.108", 10023)

_SALT = "salt"
_ITERATION_COUNT = "iteration_count" # minimum recommended for SCRAM
_STORED_KEY = "stored_key"
_SERVER_KEY = "server_key"
_IT_CNT_MIN = "4096"

# TODO: Remove and implement actual authentication database
_AUTH_DB = { "hayden": { _SALT:"test_salt", 
			_ITERATION_COUNT:_IT_CNT_MIN,
			_STORED_KEY:"stored",
			_SERVER_KEY:"server"
			}
		}

def listen():
	# Listen for initial client connect request
	context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
	# TODO: Make verification required, but use local CA.
	context.verify_mode = ssl.CERT_NONE
	context.load_cert_chain(certfile="/etc/ssl/certs/cert.pem")
	bind_socket = socket.socket()
	bind_socket.bind(_ADDR)
	bind_socket.listen(5)
	print("\nCONNECTED\n")
	
	while True:
		# Accept connection request from client
		newsocket, fromaddr = bind_socket.accept()
		connstream = context.wrap_socket(newsocket, server_side=True)
		print("\nACCEPTED CONNECTION\n")
		try:
			# TODO: Step SER.1. Upon receive first client request,
			# process fields...
			# n=<support_cb_flag>,m=<optional_field>,n=<username>,
			# r=<nonce>.
			# Load corresponding user information and respond by 
			# sending iteration count and salt to user.
			msg = connstream.recv(4096)
			print(msg)

			msg = process_initial_client_response(msg)
			print(msg)

			connstream.send(msg)

			# TODO: Step SER.2.1. When Client Proof received, 
			# compute client
			# signature, XOR that with client proof and hash 
			# client_key. After, check that result matches 
			# stored key. If yes, authentication successful. 
			# Otherwise, failed.
			msg = connstream.recv(4096)
			print(msg)

			# TODO: Step SER.2.2. If successful, Compute Server 
			# Proof using same method as client proof and send 
			# to client.
			pass
		finally:
			connstream.shutdown(socket.SHUT_RDWR)
			connstream.close()

# Process the initial client response message.
# 	message: Bytearray. Received message from client.
def process_initial_client_response(message):
	# TODO: Parse as byte array?
	msg = helper.bytes_to_string(message)
	user, nonce, channel_binding, options = parse_initial(msg)

	# Append server nonce to client nonce
	nonce += "server_nonce"

	# Get user information from auth database
	info = get_user_data(user)

	# Return iteration count and salt to client
	# as per the requirements in the RFC
	return first_server_challenge(  info[_SALT],
					info[_ITERATION_COUNT],
					nonce )

# Parse the contents of the initial client response
def parse_initial(message):
	split_msg = helper.parse(message)
	# TODO: More effective manner of reordering. This is unacceptable.
	# Only for presentation purposes 
	tmp = [split_msg[2], split_msg[3], split_msg[0], split_msg[1]]
	return tuple(tmp)

def get_user_data(user_id):
	# TODO: User_id shouldn't be username
	return _AUTH_DB[user_id]

def first_server_challenge(salt, iteration_count, nonce):
	msg=""
	msg+="r=" + nonce + ","
	msg+="s=" + salt + ","
	msg+='i=' + iteration_count
	return helper.string_to_bytes(msg)

if __name__=='__main__':
	listen()
