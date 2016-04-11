#
#	SASL helper objects
#	@author: Hayden McParlane
#	@creation-date: 4.10.2016
import ssl

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

