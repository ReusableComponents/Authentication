#
#	SASL helper objects
#	@author: Hayden McParlane
#	@creation-date: 4.10.2016
import ssl
import socket

# Factories
_SASL_FACTORY = SASLFactory()

# SASL mechanism types
_CLIENT_FIRST = ClientFirst.__class__.__name__

# SASLClient state values
_CONNECTED = "connected"

# TODO: HIGH Refine connection mechanism because in current form, every
# mechanism action will require a new call to connect upon completion.
# See SSL().connect() and implementation below.
class SASLClient(StateHolder):
	def __init__(self, mechanism, security_layer):
		self.mech, self.sl = _SASL_FACTORY.get(mechanism, security_layer)

	def authenticate(self, user, password, channel_binding=False):
		if self.is_connected():
			with security_layer as sl:
				mech.authenticate( user, password, 
					   channel_binding, security_layer )
		else:
			raise ValueError()

	def connect(self, dest_hostname, dest_port):
		security_layer.connect(dest_hostname, dest_port)
		self.add(_CONNECTED, True)

	def is_connected(self):
		return self.get(_CONNECTED)

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
		super(self, MechanismType).__init__(_CLIENT_FIRST)

class SCRAM(MechanismInterface, ClientFirst):
	pass

class SecurityLayerInterface(object):
	def connect(self, hostname, port):
		raise NotImplementedError()

class SSL(SecurityLayerInterface):
	def __init__(self):
		# TODO: Ensure SSL settings are sufficient.
		# After school presentation, implement using
		# create_default_context() until aware of all desired
		# settings
		self.context = ssl.SSLContext()
		self.context.verify_mode = ssl.CERT_NONE
		self.context.load_verify_locations("/etc/ssl/certs/ca-certificates.crt")
		self.context.load_cert_chain("/etc/ssl/certs/cert.pem")
		self.set_connection(None)

	# TODO: Verify the logic below. Does this do what stackoverflow
	# suggested?	
	def __enter__(self):
		return self.conn

	def connect(self, dest_hostname, dest_port):
		context = self.context
		self.set_connection( 
			context.wrap_socket( sock = socket.socket(socket.AF_INET),
					     server_hostname=dest_hostname )  )
		self.get_connection().connect((dest_hostname, dest_port))

	def set_connection(self, conn):
		self.conn = conn

	def get_connection(self):
		return self.conn

	def __exit__(self, exc_type, exc_value, traceback):
		try:
			self.get_connection().close()
		except Exception as e:
			raise ValueError("Connection not active")

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

class SASLFactory(FactoryCollection):
	_m = "mechanisms"
	_sl = "security_layer"
	_strat = "sasl_strategy"
	def __init__(self):
		super(self, Factory).__init__()
		self.create_factories( [_m, _sl, _strat] )

	def get(self, mechanism, security_layer):
		mech = self.get_mechanism(mechanism)
		sl = self.get_security_layer(security_layer)
		return ( mech, sl )

	def get_mechanism(self, identity):
		if self.exists(_m, identity):
			return self.get(_m, identity)
		else:
			raise KeyError("Mechanism doesn't exist: " + identity)

	def get_security_layer(self, identity):
		if self.exists(_sl, identity):
			return self.get(_sl, identity)
		else:
			raise KeyError("Security Layer doesn't exist: " 
						+ identity)

	def get_strategy(self, identity):
		if self.exists(_strat, identity):
			return self.get(_strat, identity)
		else:
			raise KeyError("SASL Strategy doesn't exist: "
						+ identity)

class FactoryCollection(object):
	# TODO: Should factories be so easily accessible?
	# Redesign?`
	factories = dict()
	
	def create_factory(self, name, overwrite=False):
		if name in FactoryCollection.factories:
			raise KeyError()
		else:
			FactoryCollection.factories[name] = dict()
	
	def create_factories(self, names):
		for name in names:
			self.create_factory(name)

	def add(self, factory, pairs):
		self.update(factory, pairs)

	def update(self, factory, pairs):
		for key, value in pairs:
			FactoryCollection.factories[factory][key] = value

	def get(self, factory, subtype):
		return FactoryCollection.factories[factory][subtype]

	def exists(self, factory, subtype=None):
		answer = False
		if subtype is None:
			return ( factory in FactoryCollection.factories )
		else:
			return ((factory in FactoryCollection.factories) and
				(subtype in FactoryCollection.factories[factory]))
			

########################### OLD BELOW #############################

class SecurityLayer(object):
        '''Abstract security layer implementation following SASL'''
        pass

class TLS(SecurityLayer):
        pass

class SecurityLayerFactory(object):
	'''Factory to fetch concrete security layer objects.'''
	_sl_catalog = {
					"tls": TLS ,
					"ssl": ssl.SSLContext
					}

	@classmethod   
	def lookup(cls, sl_type):
		'''Check hash table for type.'''
		if sl_type not in cls._sl_catalog:
			raise TypeError("Type not found: " + sl_type)
		else:
			return cls._sl_catalog[sl_type]

	@classmethod
	def get(cls, sl_type):
		sl = cls.lookup(sl_type)
		# TODO: Make more general. Initially experimenting with
		# SSLCOntext object, so the constructor value will be
		# hardcoded to follow SSLContext constructor.
		instance = sl(ssl.PROTOCOL_SSLv23)
		return instance

# TODO: Complete string prep. Initially, will avoid so as to save time for
# school presentation.
def string_prep(string, prep_type="sasl"):
	'''Prep simple unicode username or password for internationalized
	comparison''' 
	pass

