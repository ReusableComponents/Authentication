######################################################################
#	Helper functions for SCRAM SHA1
#	@author: Hayden McParlane
#	@creation-date: 4.12.2016
######################################################################
from serial.serialutil import to_bytes

######################################################################
#	General
######################################################################

# Convert string to byte array for send over port
def to_string(bytes, encoding="utf-8"):	
	return bytes.decode(encoding=encoding)

def to_bytes(string, encoding="utf-8"):
	return bytes(string, encoding=encoding)

def receive_to_string(connection, byte_count=4096):
	return to_string(connection.recv(byte_count))

def send_to_bytes(connection, string):		
	connection.send(_to_bytes(string))
	
def xor_bytes(string1, string2):
	b1 = bytes(string1)
	b2 = bytes(string2)
	if len(b1) != len(b2):
		raise ValueError()
	result = list()
	for i in range(len(b1) - 1):
		result.append( b1[i] ^ b2[i] )
	return to_string(result)

def hmac(key, string, alg="sha1"):
	h = hmac.new(key, digestmod=alg)
	h.update(string)
	return to_string(h.digest())

def hash(string, alg="sha1"):
	hash_type = _hashes[alg]
	h = hash_type()
	h.update(string)
	return to_string(h.digest())

######################################################################
#	SCRAM Formatting
######################################################################

# TODO: Implement messageformat
def parse(message, messageformat="scram"):
	crude_msg = message.split(',')
	split_msg = list()
	# Entries are of form 'n=val'. We're only interested
	# in val. Eliminate attribute characters.
	for entry in crude_msg:
		field = entry.split('=')
		split_msg.append(field[len(field) - 1])
	return split_msg

class StateHolder(object):
	def __init__(self):
		self.state = dict()

	def add(self, key, value):
		self.update(key, value)

	def update(self, key, value):
		self.state[key] = value

	def get(self, key):
		if self.exists(key):
			return self.state[key]
		else:
			raise KeyError()

	def remove(self, key):
		del self.state[key]

	def exists(self, key):
		if key in self.state:
			return True
		else:
			return False

class TypeIndependent(object):
	'''This class stores objects and provides functionality for 
	accessing that same object in different forms (i.e, bytes can
	be seamlessly accessed as strings, etc)'''
	_STR = "string"
	_BYT = "byte"
	converters = { _STR:self._to_string, _BYT: self._to_bytes }
	
	def __init__(self, value = None):
		object.__init__(self)
		self.set_value(value)
		
	def update(self, value):
		self.set_value(value)
		
	def string(self):		
		converted_value = self.perform_conversion(self._get_value(), _STR)
		return to_string(bytes, encoding)
	
	def _to_string(self, value):
		if isinstance(value, bytearray):		
			result = helper.to_string(value)
		elif isinstance(value, str):
			return value
		else:
			raise NotImplementedError("Unimplemented type conversion encountered")
			
	def bytes(self):		
		converted_value = self.perform_conversion(self._get_value(), _BYT)
		return to_string(bytes, encoding)
			
	def _to_bytes(self, value):		
		if isinstance(value, str):		
			result = helper.to_bytes(value)
		elif isinstance(value, bytearray):
			return value
		else:
			raise NotImplementedError("Unimplemented type conversion encountered		
	
	def perform_conversion(self, value, type):
		converter = self._get_converter(type)
		try:
			result = converter(value)
			return result
		except Exception as e:
			print(e)
		
	def _get_converter(self, type):
		conv = converters[type]
		
	def _set_value(self, value):
		self.value = value
		
	def _get_value(self):
		return self.value		
		
class SecurityType(TypeIndependent):
	def __init__(self, val=None):
		TypeIndependent.__init__(self, val)
	
	def hash(self, plaintext, alg="sha1"):
		return hash(self.string(), alg)
	
	def hmac(self, plaintext, key, alg):
		return hmac(key, self.string(), alg)
	
	def xor(self, val1, val2):
		return xor_bytes(self.string(), val2)
	
	def ihash(self, key, iteration_count, base_value, alg="sha1"):
		hashfcn = hmac.new(key, digestmod=alg)		
		hashtext = base_value
		for i in range(iteration_count):
			hashfcn.update(hashtext)
			hashtext = hashfcn.digest()
		return hashtext
	
class AuthenticationType(SecurityType):
	def __init__(self):
		SecurityType.__init__(self)
		
def _iterated_hash(self, string, salt, i, alg="sha1"):
	value = self._to_bytes(salt + "0001")
	key = bytearray()
	# TODO: Allow for different types of digests to be used.
	sha = hmac.new(key, digestmod=alg)
	result = None
	for i in range(int(i)):
		sha.update(value)
		result = sha.digest()
		value = result
	return self._to_string(result)

def xor_bytes(string1, string2):
	b1 = bytes(string1)
	b2 = bytes(string2)
	if len(b1) != len(b2):
		raise ValueError()
	result = list()
	for i in range(len(b1) - 1):
		result.append( b1[i] ^ b2[i] )
	return to_string(result)

def hmac(key, string, alg="sha1"):
	h = hmac.new(key, digestmod=alg)
	h.update(string)
	return to_string(h.digest())

def hash(string, alg="sha1"):
	hash_type = _hashes[alg]
	h = hash_type()
	h.update(string)
	return to_string(h.digest())		
	
class NetworkAdapter(object):
	KEY_VALUE = 'kv'
	STANDALONE = 'single_value'
	
	# TODO: HIGH NetworkAdapter should be loaded with a function call
	# that internally populates an OrderedDict() or list. That way the user
	# can enforce order among the fields entered.
	
	def __init__(self):		
		object.__init__(self)
	
	@classmethod
	def send(self, connection, auth_obj):
		message = auth_object.bytes()
		connection.send(message)
		
	@classmethod
	def receive(self, connection, byte_count=4096):
		message = connection.recv(byte_count)
		ao = AuthenticationObject(message)
		return ao
	
	def split_on(self, msg_separator):
		self.set_message_separator(separator)			
		
	def set_field_separator(self, value):
		self.fsep = value
		
	def get_field_separator(self):
		return self.fsep
	
	def set_message_separator(self, value):
		self.msep = value
		
	def get_message_separator(self):
		return self.msep
	
	def is_message_separated(self):
		pass
		
	def is_field_separated(self):
		pass
		
	def accept_format(self, format, field_separator=None):
		self.set_format(format)
		if field_separator is not None:
			self.set_field_separator(field_separator)
		
	def set_format(self, format):
		self.form = format
		
	def get_format(self):
		return self.form
		
class AuthAdapter(AdapterType):
	
	def __init__(self, val=None):
		TypeIndependent.__init__(self, val)
		
	def 