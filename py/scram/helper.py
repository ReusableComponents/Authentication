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
