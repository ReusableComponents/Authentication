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
	#ba = bytearray()
	#string = string.encode("utf-8").strip()
	#ba.extend(map(ord, string))
	return string.encode("utf-8").strip()

def bytes_to_string(byte_array, encoding="utf-8"):
	return byte_array.decode(encoding).strip()
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
