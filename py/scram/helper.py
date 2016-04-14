######################################################################
#	Helper functions for SCRAM SHA1
#	@author: Hayden McParlane
#	@creation-date: 4.12.2016
######################################################################

######################################################################
#	General
######################################################################

# Convert string to byte array for send over port
def string_to_bytes(string):
	ba = bytearray()
	ba.extend(map(ord, string))
	return ba

def bytes_to_string(byte_array, encoding="utf-8"):
	return byte_array.decode(encoding)
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

