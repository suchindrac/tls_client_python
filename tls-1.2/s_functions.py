import sys
from struct import *
from string import *
import constants
from constants import *

###############################################################################
#
# s2hs --
#
# 			Function to convert a string to a hexadecimal string
#
# Results:
#			1. Takes a string
#			2. Converts ascii value of each character to hex
#			3. Creates a string of hex values by concatenating
#			4. Returns concatenated value
#
# Example:
#			s2hs('ab') = '0x61 0x62 '
#
# Side Effects:
#			None
###############################################################################
def s2hs(s):
		hexStr = ''
		for char in s:
			asciiValue = hex(ord(char))
			hexStr = str(hexStr) + asciiValue + ' '
		return hexStr


###############################################################################
#
# hs2i --
#
# 			Function to hexadecimal string (from start pos to end pos) to
# 			 integer value
#
# Results:
#			1. Takes a string, starting position and ending position as input
#			2. Converts the two bytes at starting position and ending position
#				to Integar
#			3. Returns the integer
# 				Note: Maximum value of converted Integer is 32767 (0x7fff)
#
# Example:
#			hs2i('\x00\xcd', 0, 1) = 205
#			hs2i('\x7f\xff', 0, 1) = 32767
#			hs2i('\xaa\xbb\x7f\xff', 2, 3) = 32767
#
# Side Effects:
#			None
###############################################################################
def hs2i(string, start_pos, end_pos):
	value = 0
	power = 1
	while end_pos >= start_pos:
		b = unpack("B", string[end_pos])[0] & 0xf
		value = value + (b * power)
		power = power * 16
		b = (unpack("B", string[end_pos])[0] & 0xf0) >> 4
		value = value + (b * power)
		end_pos = end_pos - 1
		power = power * 16

	return value


###############################################################################
#
# pack_3_bytes --
#
#			Function to create a 3 byte hex string containing integer value
#
# Results:
#			1. Takes a integer as input
#			2. Creates a 3 byte hex string representing integer and returns it
#
# Side Effects:
#			None
###############################################################################
def pack_3_bytes(hex_integer):
	b3 = hex_integer & 0xff
	b2 = (hex_integer >> 8) & 0xff
	b1 = (hex_integer >> 16) & 0xff
	content = pack('BBB', b1, b2, b3)

	return content

###############################################################################
#
# pack_2_bytes --
#
#			Function to create a 2 byte hex string containing integer value
#
# Results:
#			1. Takes a integer as input
#			2. Creates a 2 byte hex string representing integer and returns it
#
# Side Effects:
#			None
###############################################################################
def pack_2_bytes(hex_integer):
	b2 = hex_integer & 0xff
	b1 = (hex_integer >> 8) & 0xff
	content = pack('BB', b1, b2)

	return content

###############################################################################
#
# get_random_string --
#
#			Function to create a random string of num_bytes
#
# Results:
#			1. Takes num_bytes as input
#			2. Creates random string of num_bytes and returns it
#
# Side Effects:
#			None
###############################################################################
def get_random_string(self, num_bytes):
	word = ''
	for i in range(num_bytes):
    		word += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	return word
