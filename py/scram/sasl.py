#
#	SASL helper objects
#	@author: Hayden McParlane
#	@creation-date: 4.10.2016
import ssl
import socket
import hashlib
import hmac
import helper
from helper import StateHolder as StateHolder

class MechanismInterface(object):
	def supports_channel_binding(self):
		raise NotImplementedError()

class MechanismType(object):
	'''Mechanism type associated with SASL mechanism.'''
	def __init__(self, mechanism_type):
		self.mechanism_type = mechanism_type

	def mechanism_type(self):
		return self.mechanism_type

class ClientFirst(MechanismType):
	def __init__(self):
		print(_CLIENT_FIRST)
		super().__init__(_CLIENT_FIRST)

	def authenticate(self, security_layer, user, password, channel_binding=False, options=None):
		raise NotImplementedError()

	def _format(self, data):
		raise NotImplementedError()

	def _initial(self):
		raise NotImplementedError()

class SCRAM(MechanismInterface, ClientFirst, StateHolder):
	_channel_bind = "cbind"
	_client_bare = "client_bare"
	_client_nonce = "client_nonce"
	_client_key = "client_key"
	_csig = "client_sig"
	_ssig = "server_sig"
	_stored_key = "stored_key"
	_server_key = "server_key"
	_salted_pass = "spass"
	_auth_msg = "auth_msg"
	_attr_nonce = "r"
	_attr_salt = "s"
	_attr_iterc = "i", 
	_attr_bind="c"
	_attr_proof="p"
	_bytes = 4096
	_hashes = { "sha1":hashlib.sha1 }

	def authenticate(self, security_layer, user, password, 
		channel_binding=False, options=None):
		with security_layer as conn:
			# . Sends initial response of form <channel_binding_flag>,
			# <optionals>,n=<user_id>,r=<secure_nonce>
			nonce = self._nonce()
			r1 = self._initial(user, nonce)
			self.add(_client_nonce, nonce)
			self.add(_client_bare, r1)
			conn.send(r1)
			challenge = conn.recv(_bytes)

			# . Validate nonce
			if not self.get(_client_nonce) in challenge:
				raise ValueError()

			data = self._parse(challenge)
			# . Compute client proof
			
			# . TODO: Normalize password
			spass = self._salt(password, data[_attr_salt], 
					data[_attr_iterc])
			client_key = self._hmac(spass, "Client Key")
			stored_key = self._hash(client_key)

			client_bare = self.get(_client_bare)
			client_final = {_attr_bind:"biws", # TODO: Imp bind
					_attr_nonce:data[_attr_nonce]}

			auth_msg = self._join( [client_bare, challenge, 
						self._join(client_final)] )
			client_signature = self._hmac(stored_key, auth_msg)

			client_proof = list()
			for i in range(len(client_key) - 1):
				client_proof.append(
					client_key[i] ^ client_signature[i] 
				)
			print(client_proof)

			client_final[_attr_proof] = client_proof
			
			# . Send Challenge 1 response
			r2 = self._format(client_final)
			conn.send(r2)

			answer = conn.recv(_bytes)
			# . Validate server

	
	def _initial(self, user, nonce, channel_binding=False):
		data = { "n":user, "r":nonce }
		return self._to_bytes("n,," + self._format(data))

	# TODO: Implement specifiable formatting later
	def _format(self, data, encoding="utf-8"):
		string = []
		for attr, value in data.items():
			string.append(attr + "=" + value)
		return self._join(string)

	def _join(self, lst):
		return ','.join(lst)

	def _parse(self, msg):
		msg = msg.split(",")
		data = dict()
		for pair in msg:
			tmp = pair.split("=")
			data[tmp[0]] = tmp[1]
		return data

	def _nonce(self):
		return self._to_bytes(nonce())

	def _to_bytes(self, string):
		return helper.string_to_bytes(string)

	def _hmac(self, key, string, alg="sha1"):
		h = hmac.new(key, digestmod=alg)
		h.update(string)
		return h.digest()

	def _iterated_hash(string, salt, i):
		value = salt + self._to_bytes("0001")
		key = bytearray()
		# TODO: Allow for different types of digests to be used.
		sha = hmac.new(key, digestmod="sha1")
		result = None
		for i in range(int(i)):
			sha.update(value)
			result = sha.digest()
			value = result
		return result

	def _hash(string, alg="sha1"):
		hash_type = _hashes[alg]
		h = hash_type()
		h.update(string)
		return h.digest()
	
	def _salt(self, password, salt, iteration_count):
		return self._iterated_hash(password, salt, iteration_count)

class SecurityLayerInterface(object):
	def __enter__(self):
		raise NotImplementedError()

	def connect(self, hostname, port):
		raise NotImplementedError()

	def send(self, byte_array):
		raise NotImplementedError()

	def __exit__(self):
		raise NotImplementedError()

class SSL(SecurityLayerInterface, StateHolder):
	_CONNECTED = "connected"
	
	def __init__(self):
		super().__init__()
		# TODO: Ensure SSL settings are sufficient.
		# After school presentation, implement using
		# create_default_context() until aware of all desired
		# settings
		self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
		self.context.verify_mode = ssl.CERT_NONE
		self.context.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
		self.context.load_cert_chain("/etc/ssl/certs/cert.pem")
		self._set_connection(None)

	# TODO: HIGH Verify the logic below. Does this do what stackoverflow
	# suggested? Refactor and just forego with usage? Using this method,
	# the object returned by _get_connection() will vary based on the 
	# SecurityLayerInterface used which means the mechanism code will
	# break as soon as a new implementation is tried. Investigate.
	def __enter__(self):
		self._connect()
		return self._get_connection()
	
	def connect(self, dest_hostname, dest_port):
		# Lazily evaluate connection
		self._set_dest_hostname(dest_hostname)
		self._set_dest_port(dest_port)
		super().add(_CONNECTED, True)		

	def _connect(self):
		dest_hostname = self._get_dest_hostname()
		dest_port = self._get_dest_port()
		if not super().get(_CONNECTED):
			raise ValueError()
		else:
			context = self.context
			self._set_connection( 
				context.wrap_socket( sock = socket.socket(socket.AF_INET),
					    server_hostname=dest_hostname )  )
			self._get_connection().connect((dest_hostname, dest_port))

	def _set_connection(self, conn):
		self.conn = conn

	def _get_connection(self):
		return self.conn
	
	def _set_dest_hostname(self, dest_hostname):
		self.dhn = dest_hostname
	
	def _get_dest_hostname(self):
		return self.dhn
	
	def _set_dest_port(self, port):
		self.dport = port
	
	def _get_dest_port(self):
		return self.dport
	
	def _set_context(self, context):
		self.context = context
		
	def _get_context(self):
		return self.context

	def __exit__(self, exc_type, exc_value, traceback):
		try:
			self._get_connection().close()
		except Exception as e:
			raise ValueError("Connection not active")			

class FactoryCollection(object):
	# TODO: Should factories be so easily accessible?
	# Redesign?`
	factories = dict()
	
	@classmethod
	def create_factory(self, name, overwrite=False):
		if name in FactoryCollection.factories:
			raise KeyError()
		else:
			FactoryCollection.factories[name] = dict()
	
	@classmethod
	def create_factories(self, names):
		for name in names:
			self.create_factory(name)

	@classmethod
	def add(self, factory, pairs):
		self.update(factory, pairs)

	@classmethod
	def update(self, factory, pairs):
		print(pairs)
		for key, value in pairs.items():
			FactoryCollection.factories[factory][key] = value

	@classmethod
	def get(self, factory, subtype):
		return FactoryCollection.factories[factory][subtype]

	@classmethod
	def exists(self, factory, subtype=None):
		answer = False
		if subtype is None:
			return ( factory in FactoryCollection.factories )
		else:
			return ((factory in FactoryCollection.factories) and
				(subtype in FactoryCollection.factories[factory]))


_m = "mechanisms"
_sl = "security_layer"
_strat = "sasl_strategy"
_sl_entries = { "ssl":SSL }
_m_entries = { "scram":SCRAM }
class SASLFactory(FactoryCollection):

	def __init__(self):
		self.create_factories( [_m, _sl, _strat] )
		self.add(_sl, _sl_entries)
		self.add(_m, _m_entries)

	def get(self, mechanism, security_layer):
		mech = self.get_mechanism(mechanism)
		sl = self.get_security_layer(security_layer)
		return ( mech, sl )

	def get_mechanism(self, identity):
		print(identity)
		if self.exists(_m, identity):
			return FactoryCollection.get(_m, identity)
		else:
			raise KeyError("Mechanism doesn't exist: " + identity)

	def get_security_layer(self, identity):
		if self.exists(_sl, identity):
			return FactoryCollection.get(_sl, identity)
		else:
			raise KeyError("Security Layer doesn't exist: " 
						+ identity)

	def get_strategy(self, identity):
		if self.exists(_strat, identity):
			return FactoryCollection.get(_strat, identity)
		else:
			raise KeyError("SASL Strategy doesn't exist: "
						+ identity)


# TODO: HIGH Refine connection mechanism because in current form, every
# mechanism action will require a new call to connect upon completion.
# See SSL().connect() and implementation below.
class SASLClient(StateHolder):
	def __init__(self, mechanism, security_layer, connect=None):
		super().__init__()
		mech, sl = _SASL_FACTORY.get(mechanism, security_layer)
		self._setmech(mech())
		self._setsl(sl())

	def authenticate(self, user, password, channel_binding=False):
		if self.is_connected():
			with self._getsl() as sl:
				self.mech.authenticate( sl, user, password, channel_binding)
		else:
			raise ValueError()

	def connect(self, dest_hostname, dest_port):
		self._getsl().connect(dest_hostname, dest_port)
		super().add(_CONNECTED, True)

	def is_connected(self):
		return super().get(_CONNECTED)
	
	def _getsl(self):
		return self.sl
	
	def _setsl(self, sl):
		self.sl = sl
		
	def _getmech(self):
		return self.mech
	
	def _setmech(self, mech):
		self.mech = mech


#########################################################################
# Helper Functions
#########################################################################

# Generate a secure, pseudo-random nonce string
def nonce():
	return "secure_random_nonce!"

# Factories
_SASL_FACTORY = SASLFactory()

# SASL mechanism types
_CLIENT_FIRST = ClientFirst.__name__

# SASLClient state values
_CONNECTED = "connected"


def main():
	client = SASLClient("scram", "ssl")

if __name__=="__main__":
	main()
