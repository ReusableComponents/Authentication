#
#	SCRAM Server
#	@author: Hayden McParlane
#	@creation-date: 4.9.2016

import sasl
from sasl import SecurityLayerFactory
import ssl
import socket

_ADDR = ("159.203.246.108", 10023)

_SALT = "salt"
_ITERATION_COUNT = "iteration_count" # minimum recommended for SCRAM
_IT_CNT_MIN = 4096

# TODO: Remove and implement actual authentication database
auth_db = { "hayden": { _SALT:"", 
			_ITERATION_COUNT:_IT_CNT_MIN,
			_STORED_KEY:,
			_SERVER_KEY:
			}
		}

def listen():
	# Listen for initial client connect request
	context = create_default_context(ssl.Purpose.CLIENT_AUTH)
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

			# TODO: Step SER.2.1. When Client Proof received, compute client
			# signature, XOR that with client proof and hash 
			# client_key. After, check that result matches 
			# stored key. If yes, authentication successful. 
			# Otherwise, failed.

			# TODO: Step SER.2.2. If successful, Compute Server 
			# Proof using same method as client proof and send 
			# to client.
		finally:
			connstream.shutdown(socket.SHUT_RDWR)
			connstream.close()
