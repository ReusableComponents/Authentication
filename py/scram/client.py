#
#	SCRAM Client
#	@author: Hayden McParlane
#	@creation-date: 4.9.2016
from sasl import SecurityLayerFactory
import ssl
import socket
import codecs

_ADDR_HOSTNAME = "159.203.246.108"
_ADDR_PORT = 10023

# TODO: Authenticate should have SCRAM as possible input. SCRAM isn't only auth
# mechanism. Therefore, the application should be decoupled from the mechanism.
# The authenticate function should be present at a higher level of abstraction
# calling the scram type of authentication.
def authenticate(authentication_user, password, server_hostname, server_port, authorization_users=None, hash_type="sha-1", channel_bind=True, channel_bind_type="tls-unique"):
	'''Authenticate against SCRAM server.
		authentication_user: String. The user authenticating against
			the server.
		password: String. The password associated with the 
			authentication_user.
		server_hostname: String. Hostname of the server being
			authenticating the user.
		server_port: Integer. Port on which the server is listening.
		authorization_users: List. The user(s) whose permissions the 
			authentication_user will assume. If not provided,
			authentication_user is treated as authorization_user.
		hash_type: The hash algorithm to use.
		channel_bind: Boolean. Indicates whether channel binding
			should be applied. True = Yes, False = No.
		channel_bind_type: String. The channel binding type to apply.
		'''
	success = False
	context = SecurityLayerFactory.get("ssl")
	# TODO: Change verify_mode to CERT_REQUIRED and create local CA or
	# something. The smart system will need to check certificates and 
	# the controller will need to act as the CA.
	context.verify_mode = ssl.CERT_NONE
	#context.check_hostname = True
	context.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
	context.load_cert_chain("/etc/ssl/certs/cert.pem")
	#context.load_verify_locations("/home/hayden/projects/github/Authentication/py/scram/cert.pem")
	# TODO: Hardcoded to follow SSLContext object interface.
	# Review and refine interface if necessary.
	conn = context.wrap_socket(
				sock=socket.socket(socket.AF_INET), 
				server_hostname=server_hostname
				)
	# TODO: Make sure port is dynamically assigned, not hardcoded.
	result = conn.connect((server_hostname, server_port))
	print(result) # DEBUG statement

	# TODO: HIGH Implement with channel bindings

	# TODO: Step CLI.1. Generate authentication request to server. Request
	# MUST be of form...	
	# n=<support_cb_flag>,m=<optional_field>,n=<username>,r=<nonce>
	req = string_to_bytes("n,,n=hayden,r=nonce")

	# TODO: HIGH ensure all bytes are sent in accordance with python docs.
	# send() returns the number of bytes sent, but may not match that 
	# intended.
	conn.send(req)

	# TODO: Step CLI.2. When response received, calculate client proof and
	# send to server for authentication.

	# TODO: Step CLI.3. If auth request successful, calculate server
	# signature, XOR with server proof to recover server key and
	# compare with known server key. If 

	success = True
	
	return success

#
#	HELPER FUNCTIONS
#

# Convert string to byte array for send over port
def string_to_bytes(string):
	ba = bytearray()
	ba.extend(map(ord, string))
	return ba

if __name__=="__main__":
	authenticate("hayden", "testpassword", _ADDR_HOSTNAME, _ADDR_PORT)
