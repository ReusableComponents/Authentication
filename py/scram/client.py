#
#	SCRAM Client
#	@author: Hayden McParlane
#	@creation-date: 4.9.2016
from sasl import SecurityLayerFactory
import helper
from helper import *
import ssl
import socket
import codecs
import hmac
import hashlib

_ADDR_HOSTNAME = "159.203.246.108"
_ADDR_PORT = 10023
# TODO: Nonce shouldn't be global. Implement better later. for presentation.
_STATE = dict()
_CLIENT_NONCE = "client_nonce"

# State manipulation functions
def client_nonce(string=None):
	if string is None:
		# Assign to nonce
		_STATE[_CLIENT_NONCE] = string
	else:
		# Return nonce value
		return _STATE[_CLIENT_NONCE]

def main():
	client = SASLClient("scram", "ssl")
	client.connect(_ADDR_HOSTNAME, _ADDR_PORT)
	client.authenticate("hayden", "password")


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
	# TODO: Hardcoded to follow SSLContext object interface.
	# Review and refine interface if necessary.
	conn = context.wrap_socket(
				sock=socket.socket(socket.AF_INET), 
				server_hostname=server_hostname
				)
	# TODO: Make sure port is dynamically assigned, not hardcoded.
	result = conn.connect((server_hostname, server_port))

	# TODO: HIGH Implement with channel bindings

	# TODO: Step CLI.1. Generate authentication request to server. Request
	# MUST be of form...	
	# n=<support_cb_flag>,m=<optional_field>,n=<username>,r=<nonce>
	username = "hayden"
	client_nonce("clientnonce!!")
	msg = initial_client_response(username, _STATE[_CLIENT_NONCE])
	_CLIENT_BARE = msg # Store for use in computation of AuthMessage

	# TODO: HIGH ensure all bytes are sent in accordance with python docs.
	# send() returns the number of bytes sent, but may not match that 
	# intended.
	conn.send(msg)
	msg = conn.recv(4096)
	print(msg)

	msg = process_first_server_challenge(msg)
	conn.send(msg)

	# TODO: Step CLI.2. When response received, calculate client proof and
	# send to server for authentication.

	# TODO: Step CLI.3. If auth request successful, calculate server
	# signature, XOR with server proof to recover server key and
	# compare with known server key. If 

	success = True
	
	return success

# Create the initial client response message to begin auth process
#	binding_flag: String. Represents desired channel binding type.
#	username: String. User's username.
#	nonce: String. Securely and randomly generated string of characters.
# TODO:	Implement options -> options: TBD
def initial_client_response(username, nonce, binding_flag="no_channel_binding", options=None):
	",".join(binding_flag, ',', 'n=' + username, 'r=' + nonce)

	# TODO: Separation of concerns. This onyl for presentation.
	return helper.string_to_bytes(msg)

def process_first_server_challenge(message):
	msg = helper.bytes_to_string(message)
	
	# Parse message
	nonce, salt, iteration_count = parse_first_challenge(msg)

	# TODO: Retrieve normalized password
	password = helper.string_to_bytes("test_password")
	print("Password: " + helper.bytes_to_string(password))

	# Check nonce to ensure initial client val present
	print("Client Nonce: " + _GLOBAL_NONCE)
	print("Returned Server Nonce: " + nonce)
	if _GLOBAL_NONCE not in nonce:
		raise ValueError(("Possible Man-in-Middle. Nonce "
					"mismatch detected."))
	
	# Calculate salted password
	salted_pass = iterated_hash(password, salt, iteration_count)

	# Calculate client key
	sha = hmac.new(salted_pass, digestmod="sha1")
	sha.update("Client Key".encode("utf-8").strip())
	client_key = sha.digest()

	# Calculate stored key
	alone_sha_hash = hashlib.sha1()
	alone_sha_hash.update(client_key)
	stored_key = alone_sha_hash.digest()

	# Calculate auth message
	auth_message = helper.string_to_bytes(_CLIENT_BARE + "," + msg) # + Client final message without proof.
					# For now just the first two to keep
					# simple.

	# Calculate client signature
	signature_hash = hmac.new(stored_key, digestmod="sha1")
	signature_hash.update(auth_message)
	client_signature = signature_hash.digest()

	# Calculate client proof
	client_proof = list()
	for i in range(len(client_key)):
		client_proof.append(client_key[i] ^ client_signature[i])

	# Format message to send to server
	result = "c=biws,r=" + str(nonce) + ",p=" + str(client_proof)
	return helper.string_to_bytes(result)

def parse_first_challenge(message):
	split_msg = helper.parse(message)
	print(split_msg)
	return tuple(split_msg)

def iterated_hash(string, salt, i):
	value = helper.string_to_bytes(salt + "0001")
	key = bytearray()
	# TODO: Allow for different types of digests to be used.
	sha = hmac.new(key, digestmod="sha1")
	result = None
	for i in range(int(i)):
		sha.update(value)
		result = sha.digest()
		value = result
	return result

def get_binding_flag(name):
	if name not in _BINDING_FLAGS:
		# TODO
		pass
	else:
		return _BINDING_FLAGS[name]

_BINDING_FLAGS = { "no_channel_binding": "n" }

class SCRAMClient(ClientState):

	# Authenticate against a SCRAMServer
	def authenticate(self, username, password):
		pass
			
	def link(self, hostname, port):
		pass

class ClientState(Client):
	def __init__(self):
		super(self, Client).__init__()
		self.state = dict()

	def add(self, key, value):
		self.update(key, value)

	def update(self, key, value):
		self.state[key] = value

	def remove(self, key):
		del self.state[key]

	def exists(self, key):
		if key in self.state:
			return True
		else:
			return False

class Client(object):
	def __init__(self):
		
	

if __name__=="__main__":
	authenticate("hayden", "testpassword", _ADDR_HOSTNAME, _ADDR_PORT)
